let servers = [];
let activeServerId = null;
let activeStatus = null;
let selectedFwZone = null;
let isLoading = false;

function toast(msg, type = "ok") {
  const area = document.getElementById("toast-area");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  area.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

async function api(url, options = {}) {
  const res = await fetch(url, {
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.detail || `HTTP ${res.status}`);
  }
  return data;
}

// Tabs
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "audit") loadAudit();
  });
});

async function loadServers(force = false) {
  if (isLoading && !force) return;
  isLoading = true;
  try {
    servers = await api("/api/servers");
    if (!activeServerId && servers.length > 0) {
      const onlineSrv = servers.find((s) => s.online);
      activeServerId = onlineSrv ? onlineSrv.id : servers[0].id;
    }
    renderServerList();
    if (activeServerId) {
      await loadActiveStatus();
    }
  } catch (err) {
    toast(`서버 목록 조회 실패: ${err.message}`, "err");
  } finally {
    isLoading = false;
  }
}

function renderServerList() {
  const ul = document.getElementById("server-list");
  ul.innerHTML = "";
  servers.forEach((srv) => {
    const li = document.createElement("li");
    li.className = `server-item ${srv.id === activeServerId ? "active" : ""}`;
    li.onclick = () => {
      activeServerId = srv.id;
      renderServerList();
      loadActiveStatus();
    };
    const dotClass = srv.online ? "online" : "offline";
    const seBadge = srv.online ? srv.selinux_mode : "Offline";
    li.innerHTML = `
      <div class="server-item-top">
        <span><span class="dot ${dotClass}"></span>${srv.name}</span>
        <button class="btn btn-danger" title="서버 삭제" onclick="deleteServer(event, '${srv.id}')">×</button>
      </div>
      <div class="server-item-sub">
        <span>${srv.url}</span>
        <span>${seBadge}</span>
      </div>
    `;
    ul.appendChild(li);
  });
}

async function loadActiveStatus() {
  if (!activeServerId) return;
  const srv = servers.find((s) => s.id === activeServerId);
  document.getElementById("srv-title").textContent = srv ? srv.name : activeServerId;

  try {
    activeStatus = await api(`/api/servers/${activeServerId}/status`);
    if (srv) {
      srv.online = true;
      srv.selinux_mode = activeStatus.selinux?.mode || srv.selinux_mode;
      renderServerList();
    }
    document.getElementById("srv-meta").textContent =
      `${activeStatus.hostname} · ${activeStatus.os} · Mode: ${activeStatus.mode}`;
    renderOverview();
    renderFirewall();
    renderSELinux();
    renderNetwork();
  } catch (err) {
    document.getElementById("srv-meta").textContent = `연결 실패: ${err.message}`;
  }
}

function getActiveProtectedPorts() {
  if (activeStatus && Array.isArray(activeStatus.protected_ports)) {
    return activeStatus.protected_ports;
  }
  const srv = servers.find((s) => s.id === activeServerId);
  return (srv && Array.isArray(srv.protected_ports)) ? srv.protected_ports : [22];
}

function renderOverview() {
  if (!activeStatus) return;
  const fw = activeStatus.firewall;
  const zoneName = fw.default_zone || "public";
  const zone = (fw.zones && fw.zones[zoneName]) || { ports: [], rich_rules: [] };

  document.getElementById("summary-cards").innerHTML = `
    <div class="stat-card">
      <div class="label">방화벽 (firewalld)</div>
      <div class="val">${fw.running ? "🟢 Running" : "🔴 Stopped"}</div>
    </div>
    <div class="stat-card">
      <div class="label">기본 Zone</div>
      <div class="val">${zoneName}</div>
    </div>
    <div class="stat-card">
      <div class="label">SELinux 모드</div>
      <div class="val">${activeStatus.selinux.mode}</div>
    </div>
    <div class="stat-card">
      <div class="label">Listen 포트 수</div>
      <div class="val">${activeStatus.listening_ports.length}</div>
    </div>
  `;

  const tbody = document.getElementById("diag-tbody");
  tbody.innerHTML = "";
  activeStatus.listening_ports.forEach((p) => {
    const spec = `${p.port}/${p.protocol}`;
    const portOpen = (zone.ports || []).includes(spec);
    const servicePortsMap = fw.service_ports || {};
    const matchedService = (zone.services || []).find((svc) =>
      (servicePortsMap[svc] || []).includes(spec)
    );
    const richMatch = (zone.rich_rules || []).some((r) => r.includes(`port="${p.port}"`));

    let fwBadge = `<span class="badge badge-err">차단됨</span>`;
    let diagBadge = `<span class="badge badge-err">외부 접속 불가 (방화벽 차단)</span>`;

    if (!p.external_exposed) {
      fwBadge = `<span class="badge badge-info">로컬 바인드</span>`;
      diagBadge = `<span class="badge badge-info">로컬 전용 (127.0.0.1)</span>`;
    } else if (portOpen) {
      fwBadge = `<span class="badge badge-ok">전체 허용</span>`;
      diagBadge = `<span class="badge badge-ok">외부 접속 가능</span>`;
    } else if (matchedService) {
      fwBadge = `<span class="badge badge-ok">서비스 허용 (${matchedService})</span>`;
      diagBadge = `<span class="badge badge-ok">외부 접속 가능 (${matchedService})</span>`;
    } else if (richMatch) {
      fwBadge = `<span class="badge badge-warn">IP 제한</span>`;
      diagBadge = `<span class="badge badge-warn">특정 IP만 허용 (Rich Rule)</span>`;
    }

    const isProtected = getActiveProtectedPorts().includes(p.port);
    const lockTag = isProtected ? ` <span title="고정 보호 포트">🔒</span>` : "";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${p.protocol.toUpperCase()}</td>
      <td><strong>${p.port}</strong>${lockTag}</td>
      <td>${p.process}</td>
      <td><code>${p.bind_ip}</code></td>
      <td>${fwBadge}</td>
      <td>${diagBadge}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Subtabs inside firewall-config
document.querySelectorAll(".subtab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".subtab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".subtab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`subtab-${btn.dataset.subtab}`).classList.add("active");
  });
});

function isFwPermanent() {
  return document.getElementById("fw-config-mode").value === "permanent";
}

function getSelectedFwZone() {
  if (!activeStatus || !activeStatus.firewall) return "public";
  const fw = activeStatus.firewall;
  if (selectedFwZone && fw.zones && fw.zones[selectedFwZone]) {
    return selectedFwZone;
  }
  return fw.default_zone || Object.keys(fw.zones || {})[0] || "public";
}

document.getElementById("fw-active-zone").addEventListener("change", (e) => {
  selectedFwZone = e.target.value;
  renderFirewall();
});

document.getElementById("fw-service-search").addEventListener("input", () => {
  renderFirewallServices();
});

document.getElementById("fw-icmp-search").addEventListener("input", () => {
  renderFirewallIcmp();
});

function formatServiceLabel(svc, servicePortsMap) {
  const ports = (servicePortsMap && servicePortsMap[svc]) || [];
  return ports.length > 0 ? `${svc} (${ports.join(", ")})` : svc;
}

function renderPortPills(ports) {
  if (!ports || ports.length === 0) {
    return `<span class="meta">포트 정의 없음 (프로토콜/모듈 기반)</span>`;
  }
  return ports.map((p) => `<span class="port-pill">${p}</span>`).join("");
}

function renderFirewallServices() {
  if (!activeStatus) return;
  const fw = activeStatus.firewall;
  const zoneName = getSelectedFwZone();
  const zone = (fw.zones && fw.zones[zoneName]) || { services: [] };
  const protectedPorts = getActiveProtectedPorts();
  const servicePortsMap = fw.service_ports || {};

  const enabledTbody = document.getElementById("fw-services-enabled");
  enabledTbody.innerHTML = "";
  const enabledList = zone.services || [];
  if (enabledList.length === 0) {
    enabledTbody.innerHTML = `<tr><td colspan="3" class="meta">허용된 서비스가 없습니다.</td></tr>`;
  } else {
    enabledList.forEach((svc) => {
      const ports = servicePortsMap[svc] || [];
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${svc}</strong></td>
        <td>${renderPortPills(ports)}</td>
        <td style="text-align: right;"></td>
      `;
      const actionTd = tr.lastElementChild;
      if (svc === "ssh" && protectedPorts.includes(22)) {
        actionTd.innerHTML = `<span class="badge badge-info">🔒 보호됨</span>`;
      } else {
        const btn = document.createElement("button");
        btn.className = "btn btn-danger";
        btn.textContent = "해제";
        btn.onclick = () => runAction("firewall/service", {
          zone: zoneName, service: svc, action: "remove", permanent: isFwPermanent(),
        });
        actionTd.appendChild(btn);
      }
      enabledTbody.appendChild(tr);
    });
  }

  const availTbody = document.getElementById("fw-services-available");
  availTbody.innerHTML = "";
  const query = (document.getElementById("fw-service-search").value || "").trim().toLowerCase();
  const enabledSet = new Set(enabledList);
  const candidates = (fw.available_services || [])
    .filter((s) => {
      if (enabledSet.has(s)) return false;
      if (!query) return true;
      const label = formatServiceLabel(s, servicePortsMap).toLowerCase();
      return label.includes(query);
    })
    .slice(0, 100);

  if (candidates.length === 0) {
    availTbody.innerHTML = `<tr><td colspan="3" class="meta">검색 결과가 없습니다.</td></tr>`;
  } else {
    candidates.forEach((svc) => {
      const ports = servicePortsMap[svc] || [];
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${svc}</strong></td>
        <td>${renderPortPills(ports)}</td>
        <td style="text-align: right;"></td>
      `;
      const btn = document.createElement("button");
      btn.className = "btn btn-sm btn-primary";
      btn.textContent = "+ 허용";
      btn.onclick = () => runAction("firewall/service", {
        zone: zoneName, service: svc, action: "add", permanent: isFwPermanent(),
      });
      tr.lastElementChild.appendChild(btn);
      availTbody.appendChild(tr);
    });
  }
}

function renderFirewall() {
  if (!activeStatus) return;
  const fw = activeStatus.firewall;
  const zones = fw.zones || {};
  const zoneNames = Object.keys(zones);
  const zoneName = getSelectedFwZone();
  selectedFwZone = zoneName;
  const zone = zones[zoneName] || {
    target: "default", interfaces: [], sources: [], services: [], ports: [],
    masquerade: false, forward_ports: [], icmp_blocks: [], rich_rules: [],
  };
  const protectedPorts = getActiveProtectedPorts();

  // Zone dropdown
  const zoneSelect = document.getElementById("fw-active-zone");
  zoneSelect.innerHTML = "";
  zoneNames.forEach((z) => {
    const opt = document.createElement("option");
    opt.value = z;
    const isDef = z === fw.default_zone ? " (default)" : "";
    const ifCount = (zones[z].interfaces || []).length;
    opt.textContent = `${z}${isDef}${ifCount ? ` [${zones[z].interfaces.join(",")}]` : ""}`;
    if (z === zoneName) opt.selected = true;
    zoneSelect.appendChild(opt);
  });

  document.getElementById("fw-zone-meta").textContent =
    `Target: ${zone.target || "default"} · Interfaces: ${(zone.interfaces || []).join(", ") || "없음"} · Sources: ${(zone.sources || []).join(", ") || "없음"}`;

  // Panic button
  const panicBtn = document.getElementById("fw-panic-btn");
  panicBtn.textContent = fw.panic_mode ? "Panic Mode: ON (해제)" : "Panic Mode: OFF";
  panicBtn.className = fw.panic_mode ? "btn btn-warn" : "btn btn-danger";

  // Protected Ports
  const protDiv = document.getElementById("protected-ports-list");
  protDiv.innerHTML = "";
  protectedPorts.forEach((portNum) => {
    const chip = document.createElement("div");
    chip.className = "chip";
    chip.innerHTML = `<span>🔒 ${portNum}</span>`;
    const btn = document.createElement("button");
    btn.className = "btn btn-danger";
    btn.textContent = "해제";
    btn.onclick = () => saveProtectedPorts(protectedPorts.filter((p) => p !== portNum));
    chip.appendChild(btn);
    protDiv.appendChild(chip);
  });

  // Services
  renderFirewallServices();

  // Ports (table rows)
  const portsTbody = document.getElementById("fw-ports-list");
  portsTbody.innerHTML = "";
  const openPorts = zone.ports || [];
  if (openPorts.length === 0) {
    portsTbody.innerHTML = `<tr><td colspan="4" class="meta">직접 개방된 포트가 없습니다.</td></tr>`;
  } else {
    openPorts.forEach((spec) => {
      const [portStr, proto] = spec.split("/");
      const portNum = parseInt(portStr, 10);
      const isProt = protectedPorts.includes(portNum);
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${portNum}</strong></td>
        <td>${(proto || "").toUpperCase()}</td>
        <td>${isProt ? '<span class="badge badge-info">🔒 보호됨</span>' : '<span class="badge badge-ok">허용</span>'}</td>
        <td style="text-align: right;"></td>
      `;
      if (!isProt) {
        const btn = document.createElement("button");
        btn.className = "btn btn-danger";
        btn.textContent = "삭제";
        btn.onclick = () => runAction("firewall/port", {
          zone: zoneName, port: portNum, protocol: proto, action: "remove", permanent: isFwPermanent(),
        });
        tr.lastElementChild.appendChild(btn);
      }
      portsTbody.appendChild(tr);
    });
  }

  // Rich Rules
  const richUl = document.getElementById("fw-rich-list");
  richUl.innerHTML = "";
  (zone.rich_rules || []).forEach((rule) => {
    const li = document.createElement("li");
    li.innerHTML = `<code>${rule}</code>`;
    const match = rule.match(/source address="([^"]+)".*port port="(\d+)" protocol="(tcp|udp)" (accept|drop|reject)/);
    if (match) {
      const btn = document.createElement("button");
      btn.className = "btn btn-danger";
      btn.textContent = "삭제";
      btn.onclick = () => runAction("firewall/rich-rule", {
        zone: zoneName,
        source_ip: match[1],
        port: parseInt(match[2], 10),
        protocol: match[3],
        rule_action: match[4],
        action: "remove",
        permanent: isFwPermanent(),
      });
      li.appendChild(btn);
    }
    richUl.appendChild(li);
  });

  // Masquerade & Forward Ports
  document.getElementById("fw-masq-state").textContent = zone.masquerade ? "ON (활성)" : "OFF (비활성)";
  const masqBtn = document.getElementById("fw-masq-btn");
  masqBtn.textContent = zone.masquerade ? "끄기" : "켜기";
  masqBtn.className = zone.masquerade ? "btn btn-warn" : "btn btn-primary";

  const fwdUl = document.getElementById("fw-forward-list");
  fwdUl.innerHTML = "";
  (zone.forward_ports || []).forEach((spec) => {
    const li = document.createElement("li");
    li.innerHTML = `<code>${spec}</code>`;
    const mPort = spec.match(/port=(\d+)/);
    const mProto = spec.match(/proto=(tcp|udp)/);
    const mToPort = spec.match(/toport=(\d+)/);
    const mToAddr = spec.match(/toaddr=([^\s:]+)/);
    if (mPort && mProto && mToPort) {
      const btn = document.createElement("button");
      btn.className = "btn btn-danger";
      btn.textContent = "삭제";
      btn.onclick = () => runAction("firewall/forward-port", {
        zone: zoneName,
        port: parseInt(mPort[1], 10),
        protocol: mProto[1],
        to_port: parseInt(mToPort[1], 10),
        to_addr: mToAddr ? mToAddr[1] : null,
        action: "remove",
        permanent: isFwPermanent(),
      });
      li.appendChild(btn);
    }
    fwdUl.appendChild(li);
  });

  // Sources & Interfaces (table rows)
  const srcTbody = document.getElementById("fw-sources-list");
  srcTbody.innerHTML = "";
  const sources = zone.sources || [];
  if (sources.length === 0) {
    srcTbody.innerHTML = `<tr><td colspan="2" class="meta">바인딩된 Source IP/CIDR이 없습니다.</td></tr>`;
  } else {
    sources.forEach((src) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><code>${src}</code></td><td style="text-align: right;"></td>`;
      const btn = document.createElement("button");
      btn.className = "btn btn-danger";
      btn.textContent = "삭제";
      btn.onclick = () => runAction("firewall/source", {
        zone: zoneName, source: src, action: "remove", permanent: isFwPermanent(),
      });
      tr.lastElementChild.appendChild(btn);
      srcTbody.appendChild(tr);
    });
  }

  const ifTbody = document.getElementById("fw-ifaces-list");
  ifTbody.innerHTML = "";
  const ifaces = zone.interfaces || [];
  if (ifaces.length === 0) {
    ifTbody.innerHTML = `<tr><td colspan="2" class="meta">할당된 인터페이스가 없습니다.</td></tr>`;
  } else {
    ifaces.forEach((iface) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><strong>${iface}</strong></td><td style="text-align: right;"></td>`;
      const btn = document.createElement("button");
      btn.className = "btn btn-danger";
      btn.textContent = "해제";
      btn.onclick = () => runAction("firewall/interface", {
        zone: zoneName, interface: iface, action: "remove", permanent: isFwPermanent(),
      });
      tr.lastElementChild.appendChild(btn);
      ifTbody.appendChild(tr);
    });
  }

  // ICMP Blocks (two clean tables: currently blocked + searchable available list)
  renderFirewallIcmp();
}

const ICMP_DESCRIPTIONS = {
  "echo-request": "Ping 요청 (차단 시 외부 Ping 응답 안 함)",
  "echo-reply": "Ping 응답",
  "timestamp-request": "ICMP 타임스탬프 요청",
  "timestamp-reply": "ICMP 타임스탬프 응답",
  "destination-unreachable": "목적지 도달 불가",
  "time-exceeded": "TTL 초과 (traceroute 등)",
  "parameter-problem": "패킷 헤더 오류",
  "redirect": "라우팅 경로 재지정",
  "source-quench": "전송 속도 감소 요청",
  "fragmentation-needed": "단편화 필요 (PMTU 탐색)",
  "packet-too-big": "패킷 크기 초과 (IPv6)",
  "port-unreachable": "포트 도달 불가",
  "host-unreachable": "호스트 도달 불가",
  "network-unreachable": "네트워크 도달 불가",
  "router-advertisement": "라우터 광고 (IPv6)",
  "router-solicitation": "라우터 요청 (IPv6)",
  "neighbour-advertisement": "이웃 광고 (IPv6 NDP)",
  "neighbour-solicitation": "이웃 요청 (IPv6 NDP)",
};

function renderFirewallIcmp() {
  if (!activeStatus) return;
  const fw = activeStatus.firewall;
  const zoneName = getSelectedFwZone();
  const zone = (fw.zones && fw.zones[zoneName]) || { icmp_blocks: [] };
  const blockedList = zone.icmp_blocks || [];
  const blockedSet = new Set(blockedList);

  const blockedTbody = document.getElementById("fw-icmp-blocked");
  blockedTbody.innerHTML = "";
  if (blockedList.length === 0) {
    blockedTbody.innerHTML = `<tr><td colspan="3" class="meta">차단 중인 ICMP 타입이 없습니다.</td></tr>`;
  } else {
    blockedList.forEach((icmp) => {
      const desc = ICMP_DESCRIPTIONS[icmp] || "-";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${icmp}</code></td>
        <td>${desc}</td>
        <td style="text-align: right;"></td>
      `;
      const btn = document.createElement("button");
      btn.className = "btn btn-danger";
      btn.textContent = "차단 해제";
      btn.onclick = () => runAction("firewall/icmp", {
        zone: zoneName, icmp_type: icmp, action: "remove", permanent: isFwPermanent(),
      });
      tr.lastElementChild.appendChild(btn);
      blockedTbody.appendChild(tr);
    });
  }

  const availTbody = document.getElementById("fw-icmp-available");
  availTbody.innerHTML = "";
  const query = (document.getElementById("fw-icmp-search").value || "").trim().toLowerCase();
  const allTypes = (fw.available_icmptypes && fw.available_icmptypes.length > 0)
    ? fw.available_icmptypes
    : Object.keys(ICMP_DESCRIPTIONS).sort();

  const candidates = allTypes.filter((t) => {
    if (blockedSet.has(t)) return false;
    if (!query) return true;
    const desc = (ICMP_DESCRIPTIONS[t] || "").toLowerCase();
    return t.toLowerCase().includes(query) || desc.includes(query);
  });

  if (candidates.length === 0) {
    availTbody.innerHTML = `<tr><td colspan="3" class="meta">검색 결과가 없습니다.</td></tr>`;
  } else {
    candidates.forEach((icmp) => {
      const desc = ICMP_DESCRIPTIONS[icmp] || "-";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${icmp}</code></td>
        <td>${desc}</td>
        <td style="text-align: right;"></td>
      `;
      const btn = document.createElement("button");
      btn.className = "btn btn-sm btn-primary";
      btn.textContent = "+ 차단";
      btn.onclick = () => runAction("firewall/icmp", {
        zone: zoneName, icmp_type: icmp, action: "add", permanent: isFwPermanent(),
      });
      tr.lastElementChild.appendChild(btn);
      availTbody.appendChild(tr);
    });
  }
}

async function fwControl(command) {
  await runAction("firewall/control", { command, zone: getSelectedFwZone() });
}

async function togglePanicMode() {
  const isOn = activeStatus?.firewall?.panic_mode;
  await runAction("firewall/control", { command: isOn ? "panic-off" : "panic-on" });
}

async function toggleMasquerade() {
  const zoneName = getSelectedFwZone();
  const current = activeStatus?.firewall?.zones?.[zoneName]?.masquerade || false;
  await runAction("firewall/masquerade", {
    zone: zoneName,
    enabled: !current,
    permanent: isFwPermanent(),
  });
}

function renderSELinux() {
  if (!activeStatus) return;
  const se = activeStatus.selinux;
  document.getElementById("se-current-mode").textContent = se.mode;

  const boolDiv = document.getElementById("se-booleans-list");
  boolDiv.innerHTML = "";
  Object.entries(se.booleans || {}).forEach(([name, val]) => {
    const row = document.createElement("div");
    row.className = "bool-item";
    row.innerHTML = `<code>${name}</code>`;
    const btn = document.createElement("button");
    btn.className = `btn btn-sm ${val ? "btn-success" : "btn-secondary"}`;
    btn.textContent = val ? "ON (끄기)" : "OFF (켜기)";
    btn.onclick = () => runAction("selinux/boolean", { name, value: !val, persistent: true });
    row.appendChild(btn);
    boolDiv.appendChild(row);
  });

  const portsUl = document.getElementById("se-ports-list");
  portsUl.innerHTML = "";
  (se.custom_ports || []).forEach((item) => {
    const li = document.createElement("li");
    li.innerHTML = `<span><strong>${item.port_type}</strong> (${item.protocol}) : ${item.ports}</span>`;
    portsUl.appendChild(li);
  });
}

function renderNetwork() {
  if (!activeStatus) return;
  const tbody = document.getElementById("net-tbody");
  tbody.innerHTML = "";
  (activeStatus.network || []).forEach((n) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${n.connection}</strong></td>
      <td>${n.device}</td>
      <td>${n.method}</td>
      <td><code>${n.address || "-"}</code></td>
      <td><code>${n.gateway || "-"}</code></td>
      <td><code>${n.dns || "-"}</code></td>
    `;
    tbody.appendChild(tr);
  });
}

async function runAction(actionPath, payload) {
  if (!activeServerId) return;
  try {
    const res = await api(`/api/servers/${activeServerId}/action/${actionPath}`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    toast(res.detail || "적용 완료", "ok");
    await loadActiveStatus();
  } catch (err) {
    toast(`실패: ${err.message}`, "err");
  }
}

async function setSELinuxMode(mode) {
  await runAction("selinux/mode", { mode });
}

async function saveProtectedPorts(ports) {
  if (!activeServerId) return;
  try {
    const res = await api(`/api/servers/${activeServerId}/protected-ports`, {
      method: "PUT",
      body: JSON.stringify({ ports }),
    });
    if (activeStatus) {
      activeStatus.protected_ports = res.protected_ports;
    }
    const srv = servers.find((s) => s.id === activeServerId);
    if (srv) {
      srv.protected_ports = res.protected_ports;
    }
    toast(`고정 보호 포트 저장됨: ${res.protected_ports.join(", ") || "없음"}`, "ok");
    renderOverview();
    renderFirewall();
  } catch (err) {
    toast(`보호 포트 저장 실패: ${err.message}`, "err");
  }
}

document.getElementById("protected-port-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = document.getElementById("protected-port-input");
  const port = parseInt(input.value, 10);
  if (!port || port < 1 || port > 65535) return;
  const current = getActiveProtectedPorts();
  if (!current.includes(port)) {
    await saveProtectedPorts([...current, port]);
  }
  input.value = "";
});

// Forms
document.getElementById("fw-port-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await runAction("firewall/port", {
    zone: getSelectedFwZone(),
    port: parseInt(document.getElementById("fw-port").value, 10),
    protocol: document.getElementById("fw-proto").value,
    action: "add",
    permanent: isFwPermanent(),
  });
});

document.getElementById("fw-rich-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await runAction("firewall/rich-rule", {
    zone: getSelectedFwZone(),
    source_ip: document.getElementById("rich-ip").value.trim(),
    port: parseInt(document.getElementById("rich-port").value, 10),
    protocol: document.getElementById("rich-proto").value,
    rule_action: document.getElementById("rich-action").value,
    action: "add",
    permanent: isFwPermanent(),
  });
});

document.getElementById("fw-forward-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await runAction("firewall/forward-port", {
    zone: getSelectedFwZone(),
    port: parseInt(document.getElementById("fwd-port").value, 10),
    protocol: document.getElementById("fwd-proto").value,
    to_port: parseInt(document.getElementById("fwd-toport").value, 10),
    to_addr: document.getElementById("fwd-toaddr").value.trim() || null,
    action: "add",
    permanent: isFwPermanent(),
  });
});

document.getElementById("fw-source-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = document.getElementById("fw-source-input");
  await runAction("firewall/source", {
    zone: getSelectedFwZone(),
    source: input.value.trim(),
    action: "add",
    permanent: isFwPermanent(),
  });
  input.value = "";
});

document.getElementById("fw-iface-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = document.getElementById("fw-iface-input");
  await runAction("firewall/interface", {
    zone: getSelectedFwZone(),
    interface: input.value.trim(),
    action: "change",
    permanent: isFwPermanent(),
  });
  input.value = "";
});

// (ICMP additions handled via table buttons in renderFirewallIcmp)

document.getElementById("se-port-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await runAction("selinux/port", {
    port_type: document.getElementById("se-type").value.trim(),
    port: parseInt(document.getElementById("se-port").value, 10),
    protocol: document.getElementById("se-proto").value,
    action: "add",
  });
});

document.getElementById("net-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await runAction("network/ipv4", {
    connection: document.getElementById("net-con").value.trim(),
    method: document.getElementById("net-method").value,
    address: document.getElementById("net-addr").value.trim() || null,
    gateway: document.getElementById("net-gw").value.trim() || null,
    dns: document.getElementById("net-dns").value.trim() || null,
  });
});

// Audit log
async function loadAudit() {
  try {
    const logs = await api("/api/audit");
    const tbody = document.getElementById("audit-tbody");
    tbody.innerHTML = "";
    logs.forEach((l) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${l.timestamp.replace("T", " ").slice(0, 19)}</td>
        <td>${l.server_name}</td>
        <td><code>${l.action}</code></td>
        <td>${l.detail}</td>
        <td>${l.success ? '<span class="badge badge-ok">성공</span>' : '<span class="badge badge-err">실패</span>'}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    toast(`감사 로그 조회 실패: ${err.message}`, "err");
  }
}

// Modal
function openAddServerModal() {
  document.getElementById("add-server-modal").classList.remove("hidden");
}
function closeAddServerModal() {
  document.getElementById("add-server-modal").classList.add("hidden");
}
document.getElementById("add-server-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const rawPorts = document.getElementById("new-srv-ports").value.trim();
  const parsedPorts = rawPorts
    ? rawPorts.split(",").map((p) => parseInt(p.trim(), 10)).filter((p) => p >= 1 && p <= 65535)
    : null;
  try {
    const created = await api("/api/servers", {
      method: "POST",
      body: JSON.stringify({
        name: document.getElementById("new-srv-name").value.trim(),
        url: document.getElementById("new-srv-url").value.trim(),
        token: document.getElementById("new-srv-token").value,
        group: document.getElementById("new-srv-group").value.trim() || "default",
        protected_ports: parsedPorts,
      }),
    });
    closeAddServerModal();
    activeServerId = created.id;
    toast("새 서버가 등록되었습니다.", "ok");
    await loadServers();
  } catch (err) {
    toast(`서버 등록 실패: ${err.message}`, "err");
  }
});

async function deleteServer(event, serverId) {
  event.stopPropagation();
  try {
    await api(`/api/servers/${serverId}`, { method: "DELETE" });
    if (activeServerId === serverId) {
      activeServerId = null;
      activeStatus = null;
    }
    toast("서버가 목록에서 삭제되었습니다.", "ok");
    await loadServers();
  } catch (err) {
    toast(`서버 삭제 실패: ${err.message}`, "err");
  }
}

async function refreshAll() {
  await loadActiveStatus();
  await loadServers(true);
}

setInterval(() => {
  if (document.getElementById("auto-refresh").checked) {
    loadServers(false);
  }
}, 10000);

loadServers();
