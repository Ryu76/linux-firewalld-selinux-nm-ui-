let servers = [];
let activeServerId = null;
let activeStatus = null;
let selectedFwZone = null;
let watchedProcesses = [];
let isLoading = false;

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getActiveMainTab() {
  const activeBtn = document.querySelector(".tab.active");
  return activeBtn ? activeBtn.dataset.tab : "overview";
}

function getActiveLogSubtab() {
  const activeBtn = document.querySelector(".log-subtab.active");
  return activeBtn ? activeBtn.dataset.logtab : "audit-db";
}

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
    if (btn.dataset.tab === "processes") loadProcessesTab();
    if (btn.dataset.tab === "audit") refreshActiveAuditSubtab();
  });
});

// Log Subtabs
document.querySelectorAll(".log-subtab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".log-subtab").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".logtab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`logtab-${btn.dataset.logtab}`).classList.add("active");
    refreshActiveAuditSubtab();
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
    let rightMeta = srv.online ? (srv.selinux_mode || "Online") : "Offline";
    if (srv.online && typeof srv.mem_percent === "number") {
      rightMeta = `MEM ${srv.mem_percent}%`;
    }
    li.innerHTML = `
      <div class="server-item-top">
        <span><span class="dot ${dotClass}"></span>${escapeHtml(srv.name)}</span>
        <div class="server-item-actions">
          <button type="button" class="btn-icon-edit" title="서버 정보 수정" onclick="editServerFromList(event, '${escapeHtml(srv.id)}')">✎</button>
          <button type="button" class="btn btn-danger" title="서버 삭제" onclick="deleteServer(event, '${escapeHtml(srv.id)}')">×</button>
        </div>
      </div>
      <div class="server-item-sub">
        <span>${escapeHtml(srv.url)}</span>
        <span>${escapeHtml(rightMeta)}</span>
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
      if (activeStatus.resources) {
        srv.cpu_percent = activeStatus.resources.cpu_percent;
        srv.mem_percent = activeStatus.resources.mem_percent;
      }
      renderServerList();
    }
    document.getElementById("srv-meta").textContent =
      `${activeStatus.hostname} · ${activeStatus.os} · Mode: ${activeStatus.mode}`;
    renderOverview();
    renderFirewall();
    const curTab = getActiveMainTab();
    if (curTab === "processes") {
      await loadProcessesTab();
    } else if (curTab === "audit") {
      await refreshActiveAuditSubtab();
    }
  } catch (err) {
    document.getElementById("srv-meta").textContent = `연결 실패: ${err.message}`;
    const curTab = getActiveMainTab();
    if (curTab === "processes") {
      await loadProcessesTab();
    } else if (curTab === "audit") {
      await refreshActiveAuditSubtab();
    }
  }
}

function getActiveProtectedPorts() {
  if (activeStatus && Array.isArray(activeStatus.protected_ports)) {
    return activeStatus.protected_ports;
  }
  const srv = servers.find((s) => s.id === activeServerId);
  return (srv && Array.isArray(srv.protected_ports)) ? srv.protected_ports : [22];
}

function meterLevelClass(pct) {
  if (pct >= 90) return "err";
  if (pct >= 75) return "warn";
  return "ok";
}

function renderOverview() {
  if (!activeStatus) return;
  const fw = activeStatus.firewall;
  const res = activeStatus.resources || {};
  const se = activeStatus.selinux || {};
  const zoneName = fw.default_zone || "public";
  const zone = (fw.zones && fw.zones[zoneName]) || { ports: [], rich_rules: [] };

  const cpuPct = typeof res.cpu_percent === "number" ? res.cpu_percent : 0;
  const memPct = typeof res.mem_percent === "number" ? res.mem_percent : 0;

  document.getElementById("summary-cards").innerHTML = `
    <div class="stat-card">
      <div class="label">방화벽 (firewalld)</div>
      <div class="val">${fw.running ? "🟢 Running" : "🔴 Stopped"}</div>
    </div>
    <div class="stat-card">
      <div class="label">가동 시간 (Uptime)</div>
      <div class="val">${escapeHtml(res.uptime_human || "-")}</div>
    </div>
    <div class="stat-card">
      <div class="label">CPU 부하 (${res.cpu_cores || 1} Core)</div>
      <div class="val">${cpuPct}%</div>
    </div>
    <div class="stat-card">
      <div class="label">메모리 사용률</div>
      <div class="val">${memPct}%</div>
    </div>
    <div class="stat-card">
      <div class="label">SELinux 모드</div>
      <div class="val">${escapeHtml(se.mode || "-")}</div>
    </div>
  `;

  // CPU & Memory Bars
  const memUsedGb = res.mem_total_mb ? (res.mem_used_mb / 1024).toFixed(1) : "0.0";
  const memTotalGb = res.mem_total_mb ? (res.mem_total_mb / 1024).toFixed(1) : "0.0";
  document.getElementById("res-cpu-mem").innerHTML = `
    <div class="meter-item">
      <div class="meter-head">
        <span><strong>CPU 부하</strong> <span class="meta">(Load Avg: ${res.load_1m ?? 0} / ${res.load_5m ?? 0} / ${res.load_15m ?? 0})</span></span>
        <strong>${cpuPct}%</strong>
      </div>
      <div class="meter-track"><div class="meter-fill ${meterLevelClass(cpuPct)}" style="width: ${Math.min(100, cpuPct)}%;"></div></div>
    </div>
    <div class="meter-item">
      <div class="meter-head">
        <span><strong>메모리 (RAM)</strong> <span class="meta">(${memUsedGb} GB / ${memTotalGb} GB)</span></span>
        <strong>${memPct}%</strong>
      </div>
      <div class="meter-track"><div class="meter-fill ${meterLevelClass(memPct)}" style="width: ${Math.min(100, memPct)}%;"></div></div>
    </div>
  `;

  // Disk Partitions Table
  const diskTbody = document.getElementById("res-disk-tbody");
  diskTbody.innerHTML = "";
  const disks = res.disks || [];
  if (disks.length === 0) {
    diskTbody.innerHTML = `<tr><td colspan="3" class="meta">디스크 파티션 정보가 없습니다.</td></tr>`;
  } else {
    disks.forEach((d) => {
      const pct = Number(d.use_percent || 0);
      const lvl = meterLevelClass(pct);
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${escapeHtml(d.mount)}</strong><div class="meta">${escapeHtml(d.filesystem)}</div></td>
        <td>${d.used_gb} / ${d.size_gb} GB <span class="meta">(여유 ${d.avail_gb}G)</span></td>
        <td>
          <div class="meter-head" style="margin-bottom: 4px;"><span class="badge badge-${lvl}">${pct}%</span></div>
          <div class="meter-track"><div class="meter-fill ${lvl}" style="width: ${Math.min(100, pct)}%;"></div></div>
        </td>
      `;
      diskTbody.appendChild(tr);
    });
  }

  // Port Cross-diagnostics
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
      fwBadge = `<span class="badge badge-ok">서비스 허용 (${escapeHtml(matchedService)})</span>`;
      diagBadge = `<span class="badge badge-ok">외부 접속 가능 (${escapeHtml(matchedService)})</span>`;
    } else if (richMatch) {
      fwBadge = `<span class="badge badge-warn">IP 제한</span>`;
      diagBadge = `<span class="badge badge-warn">특정 IP만 허용 (Rich Rule)</span>`;
    }

    const isProtected = getActiveProtectedPorts().includes(p.port);
    const lockTag = isProtected ? ` <span title="고정 보호 포트">🔒</span>` : "";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(p.protocol.toUpperCase())}</td>
      <td><strong>${p.port}</strong>${lockTag}</td>
      <td>${escapeHtml(p.process)}</td>
      <td><code>${escapeHtml(p.bind_ip)}</code></td>
      <td>${fwBadge}</td>
      <td>${diagBadge}</td>
    `;
    tbody.appendChild(tr);
  });

  // Read-only Network Interfaces
  const netTbody = document.getElementById("net-readonly-tbody");
  netTbody.innerHTML = "";
  const nets = activeStatus.network || [];
  if (nets.length === 0) {
    netTbody.innerHTML = `<tr><td colspan="6" class="meta">네트워크 인터페이스 정보가 없습니다.</td></tr>`;
  } else {
    nets.forEach((n) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${escapeHtml(n.connection)}</strong></td>
        <td>${escapeHtml(n.device)}</td>
        <td>${escapeHtml(n.method)}</td>
        <td><code>${escapeHtml(n.address || "-")}</code></td>
        <td><code>${escapeHtml(n.gateway || "-")}</code></td>
        <td><code>${escapeHtml(n.dns || "-")}</code></td>
      `;
      netTbody.appendChild(tr);
    });
  }

  // Read-only SELinux Status
  const seBox = document.getElementById("se-readonly-box");
  const modeBadge = se.mode === "Enforcing"
    ? `<span class="badge badge-ok">Enforcing (강제 보호 중)</span>`
    : `<span class="badge badge-warn">${escapeHtml(se.mode || "Unknown")}</span>`;
  const customPorts = se.custom_ports || [];
  const customPortsHtml = customPorts.length > 0
    ? customPorts.map((c) => `<li><span><strong>${escapeHtml(c.port_type)}</strong> (${escapeHtml(c.protocol)})</span><code>${escapeHtml(c.ports)}</code></li>`).join("")
    : `<li><span class="meta">별도 등록된 비표준 SELinux 포트가 없습니다.</span></li>`;
  seBox.innerHTML = `
    <div class="mode-row" style="margin-bottom: 12px;">
      <span>현재 동작 모드</span>
      ${modeBadge}
    </div>
    <h4 class="subhead">등록된 비표준 포트 레이블</h4>
    <ul class="rule-list">${customPortsHtml}</ul>
  `;
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

// ==================== Watched Processes & Recovery ====================

function formatProcessStatusBadge(status) {
  switch (status) {
    case "running":
      return `<span class="badge badge-ok">🟢 실행중</span>`;
    case "recovered":
      return `<span class="badge badge-warn">🟡 자동복구됨</span>`;
    case "stopped":
      return `<span class="badge badge-err">🔴 중지됨</span>`;
    case "recovery_failed":
      return `<span class="badge badge-err">🔴 복구 실패</span>`;
    case "unreachable":
      return `<span class="badge badge-err">⚠️ 통신 불가</span>`;
    default:
      return `<span class="badge badge-info">⚪ 미점검</span>`;
  }
}

function formatRecoveryActionLabel(action, target) {
  const safeTarget = target ? ` (<code>${escapeHtml(target)}</code>)` : "";
  switch (action) {
    case "systemctl_restart":
      return `<span class="badge badge-info">서비스 재시작</span>${safeTarget}`;
    case "script":
      return `<span class="badge badge-warn">복구 스크립트</span>${safeTarget}`;
    case "alert_only":
      return `<span class="badge badge-warn">알림 · 경고 기록</span>`;
    default:
      return `<span class="meta">조치 없음</span>`;
  }
}

async function loadProcessesTab() {
  if (!activeServerId) return;
  await Promise.all([loadWatchedProcesses(), loadProcessLogs()]);
}

async function loadWatchedProcesses() {
  if (!activeServerId) return;
  try {
    watchedProcesses = await api(`/api/servers/${activeServerId}/processes`);
    renderWatchedProcesses();
  } catch (err) {
    toast(`감시 프로세스 조회 실패: ${err.message}`, "err");
  }
}

function renderWatchedProcesses() {
  const total = watchedProcesses.length;
  const runningCnt = watchedProcesses.filter((p) => p.last_status === "running").length;
  const issueCnt = watchedProcesses.filter((p) =>
    ["stopped", "recovered", "recovery_failed", "unreachable"].includes(p.last_status)
  ).length;
  const logOnCnt = watchedProcesses.filter((p) => p.save_log).length;

  document.getElementById("proc-summary-cards").innerHTML = `
    <div class="stat-card">
      <div class="label">등록된 감시 대상</div>
      <div class="val">${total}개</div>
    </div>
    <div class="stat-card">
      <div class="label">정상 실행 중</div>
      <div class="val">${runningCnt}개</div>
    </div>
    <div class="stat-card">
      <div class="label">중지 · 복구 발생</div>
      <div class="val">${issueCnt}개</div>
    </div>
    <div class="stat-card">
      <div class="label">동작 로그 저장 활성</div>
      <div class="val">${logOnCnt} / ${total}</div>
    </div>
  `;

  // Sync process filter dropdown
  const procFilter = document.getElementById("proc-log-filter-proc");
  const prevVal = procFilter.value;
  procFilter.innerHTML = `<option value="">전체 프로세스</option>`;
  watchedProcesses.forEach((p) => {
    const opt = document.createElement("option");
    opt.value = p.id;
    opt.textContent = `${p.process_name} (${p.check_type})`;
    if (p.id === prevVal) opt.selected = true;
    procFilter.appendChild(opt);
  });

  const tbody = document.getElementById("proc-list-tbody");
  tbody.innerHTML = "";
  if (watchedProcesses.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="meta">등록된 감시 프로세스가 없습니다. 우측 상단 <strong>+ 감시 프로세스 추가</strong> 버튼으로 등록하세요.</td></tr>`;
    return;
  }

  watchedProcesses.forEach((proc) => {
    const checkedTime = proc.last_checked_at
      ? proc.last_checked_at.replace("T", " ").slice(0, 19)
      : "점검 전";
    const detailText = proc.last_action_detail ? ` · ${escapeHtml(proc.last_action_detail)}` : "";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${escapeHtml(proc.process_name)}</strong></td>
      <td><code>${escapeHtml(proc.check_type)}</code></td>
      <td>${formatProcessStatusBadge(proc.last_status)}</td>
      <td>${formatRecoveryActionLabel(proc.recovery_action, proc.recovery_target)}</td>
      <td>${proc.check_interval_sec}초</td>
      <td class="cell-enabled"></td>
      <td class="cell-savelog"></td>
      <td><span class="meta">${escapeHtml(checkedTime)}${detailText}</span></td>
      <td style="text-align: right; white-space: nowrap;" class="cell-actions"></td>
    `;

    const enabledBtn = document.createElement("button");
    enabledBtn.type = "button";
    enabledBtn.className = `toggle-pill-btn ${proc.enabled ? "on" : "off"}`;
    enabledBtn.textContent = proc.enabled ? "감시 ON" : "감시 OFF";
    enabledBtn.onclick = () => toggleProcessField(proc.id, { enabled: !proc.enabled });
    tr.querySelector(".cell-enabled").appendChild(enabledBtn);

    const logBtn = document.createElement("button");
    logBtn.type = "button";
    logBtn.className = `toggle-pill-btn ${proc.save_log ? "on" : "off"}`;
    logBtn.textContent = proc.save_log ? "저장 ON" : "저장 OFF";
    logBtn.onclick = () => toggleProcessField(proc.id, { save_log: !proc.save_log });
    tr.querySelector(".cell-savelog").appendChild(logBtn);

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "btn btn-sm btn-secondary";
    editBtn.style.marginRight = "6px";
    editBtn.textContent = "설정";
    editBtn.onclick = () => openProcessModal(proc);

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "btn btn-danger";
    delBtn.textContent = "삭제";
    delBtn.onclick = () => deleteWatchedProcess(proc.id, proc.process_name);

    const actCell = tr.querySelector(".cell-actions");
    actCell.appendChild(editBtn);
    actCell.appendChild(delBtn);
    tbody.appendChild(tr);
  });
}

async function toggleProcessField(procId, patchObj) {
  try {
    await api(`/api/processes/${procId}`, {
      method: "PATCH",
      body: JSON.stringify(patchObj),
    });
    toast("프로세스 설정이 변경되었습니다.", "ok");
    await loadWatchedProcesses();
  } catch (err) {
    toast(`설정 변경 실패: ${err.message}`, "err");
  }
}

async function deleteWatchedProcess(procId, procName) {
  try {
    await api(`/api/processes/${procId}`, { method: "DELETE" });
    toast(`'${procName}' 감시 설정이 삭제되었습니다.`, "ok");
    await loadProcessesTab();
  } catch (err) {
    toast(`삭제 실패: ${err.message}`, "err");
  }
}

async function pollActiveServerProcesses() {
  if (!activeServerId) return;
  try {
    const res = await api(`/api/processes/poll?server_id=${encodeURIComponent(activeServerId)}`, {
      method: "POST",
    });
    toast(`즉시 점검 완료 (${res.checked}개 대상 확인)`, "ok");
    await loadProcessesTab();
  } catch (err) {
    toast(`즉시 점검 실패: ${err.message}`, "err");
  }
}

async function loadProcessLogs() {
  if (!activeServerId) return;
  const procId = document.getElementById("proc-log-filter-proc").value;
  const statusVal = document.getElementById("proc-log-filter-status").value;
  const params = new URLSearchParams({ server_id: activeServerId, limit: "100" });
  if (procId) params.set("process_id", procId);
  if (statusVal) params.set("status", statusVal);

  try {
    const logs = await api(`/api/process-logs?${params.toString()}`);
    const tbody = document.getElementById("proc-logs-tbody");
    tbody.innerHTML = "";
    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="meta">기록된 프로세스 동작 로그가 없습니다.</td></tr>`;
      return;
    }
    logs.forEach((l) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(l.timestamp.replace("T", " ").slice(0, 19))}</td>
        <td><strong>${escapeHtml(l.process_name)}</strong></td>
        <td>${formatProcessStatusBadge(l.status)}</td>
        <td><code>${escapeHtml(l.action_taken)}</code></td>
        <td>${l.success ? '<span class="badge badge-ok">정상</span>' : '<span class="badge badge-err">이상</span>'}</td>
        <td>${escapeHtml(l.detail)}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    toast(`프로세스 로그 조회 실패: ${err.message}`, "err");
  }
}

function syncProcessRecoveryTargetField() {
  const action = document.getElementById("proc-recovery-action").value;
  const wrap = document.getElementById("proc-target-wrap");
  const label = document.getElementById("proc-target-label");
  const input = document.getElementById("proc-recovery-target");
  const hint = document.getElementById("proc-target-hint");

  if (action === "script") {
    wrap.style.display = "flex";
    label.textContent = "복구 스크립트 절대 경로 (필수)";
    input.placeholder = "/opt/linux-access-control-hub/scripts/recover.sh";
    input.required = true;
    hint.textContent = "보안을 위해 서버 내 절대 경로(/로 시작, .. 불가)만 허용됩니다.";
  } else if (action === "systemctl_restart") {
    wrap.style.display = "flex";
    label.textContent = "재시작할 systemd 유닛 이름 (선택)";
    input.placeholder = "비워두면 프로세스 이름과 동일한 서비스 재시작";
    input.required = false;
    hint.textContent = "예: nginx, httpd, postgresql-16";
  } else {
    wrap.style.display = "none";
    input.required = false;
    input.value = "";
    hint.textContent = "";
  }
}

function openProcessModal(proc = null) {
  if (!activeServerId) {
    toast("먼저 좌측에서 서버를 선택하세요.", "err");
    return;
  }
  document.getElementById("proc-modal-title").textContent = proc
    ? `감시 프로세스 설정 수정 (${proc.process_name})`
    : "새 감시 프로세스 추가";
  document.getElementById("proc-edit-id").value = proc ? proc.id : "";
  document.getElementById("proc-name").value = proc ? proc.process_name : "";
  document.getElementById("proc-check-type").value = proc ? proc.check_type : "process";
  document.getElementById("proc-recovery-action").value = proc ? proc.recovery_action : "alert_only";
  document.getElementById("proc-recovery-target").value = proc ? proc.recovery_target : "";
  document.getElementById("proc-interval").value = proc ? proc.check_interval_sec : 30;
  document.getElementById("proc-enabled").checked = proc ? Boolean(proc.enabled) : true;
  document.getElementById("proc-save-log").checked = proc ? Boolean(proc.save_log) : true;
  syncProcessRecoveryTargetField();
  document.getElementById("process-modal").classList.remove("hidden");
}

function closeProcessModal() {
  document.getElementById("process-modal").classList.add("hidden");
}

document.getElementById("process-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!activeServerId) return;
  const editId = document.getElementById("proc-edit-id").value.trim();
  const payload = {
    process_name: document.getElementById("proc-name").value.trim(),
    check_type: document.getElementById("proc-check-type").value,
    recovery_action: document.getElementById("proc-recovery-action").value,
    recovery_target: document.getElementById("proc-recovery-target").value.trim(),
    check_interval_sec: parseInt(document.getElementById("proc-interval").value, 10) || 30,
    enabled: document.getElementById("proc-enabled").checked,
    save_log: document.getElementById("proc-save-log").checked,
  };

  try {
    if (editId) {
      await api(`/api/processes/${editId}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      toast("감시 프로세스 설정이 수정되었습니다.", "ok");
    } else {
      await api(`/api/servers/${activeServerId}/processes`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      toast("새 감시 프로세스가 등록되었습니다.", "ok");
    }
    closeProcessModal();
    await loadProcessesTab();
  } catch (err) {
    toast(`저장 실패: ${err.message}`, "err");
  }
});

// ==================== Audit & Encrypted Agent Logs ====================

async function refreshActiveAuditSubtab() {
  const sub = getActiveLogSubtab();
  if (sub === "audit-db") {
    await loadAudit();
  } else if (sub === "agent-enc") {
    await loadAgentEncryptedLogs();
  } else if (sub === "manual-dec") {
    await loadControllerPlainLogs();
  }
}

async function loadAudit() {
  const scope = document.getElementById("audit-filter-scope")?.value || "all";
  const resultFilter = document.getElementById("audit-filter-result")?.value || "";
  const limitVal = document.getElementById("audit-filter-limit")?.value || "50";
  const params = new URLSearchParams({ limit: limitVal });
  if (scope === "active" && activeServerId) {
    params.set("server_id", activeServerId);
  }
  if (resultFilter !== "") {
    params.set("success", resultFilter);
  }

  try {
    const logs = await api(`/api/audit?${params.toString()}`);
    const tbody = document.getElementById("audit-tbody");
    tbody.innerHTML = "";
    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="meta">조건에 해당하는 감사 로그가 없습니다.</td></tr>`;
      return;
    }
    logs.forEach((l) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(l.timestamp.replace("T", " ").slice(0, 19))}</td>
        <td>${escapeHtml(l.server_name)}</td>
        <td><code>${escapeHtml(l.action)}</code></td>
        <td>${escapeHtml(l.detail)}</td>
        <td>${l.success ? '<span class="badge badge-ok">성공</span>' : '<span class="badge badge-err">실패</span>'}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    toast(`감사 로그 조회 실패: ${err.message}`, "err");
  }
}

async function loadAgentEncryptedLogs() {
  const tbody = document.getElementById("agent-enc-tbody");
  if (!activeServerId) {
    tbody.innerHTML = `<tr><td colspan="4" class="meta">먼저 좌측에서 조회할 서버를 선택하세요.</td></tr>`;
    return;
  }
  const decryptMode = document.getElementById("agent-log-decrypt-mode").value;
  const limitVal = document.getElementById("agent-log-limit").value;
  tbody.innerHTML = `<tr><td colspan="4" class="meta">Agent로부터 암호화 로그를 불러오는 중...</td></tr>`;

  try {
    const data = await api(
      `/api/servers/${activeServerId}/agent-logs?limit=${encodeURIComponent(limitVal)}&decrypt=${encodeURIComponent(decryptMode)}`
    );
    const logs = data.logs || [];
    tbody.innerHTML = "";
    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" class="meta">Agent에 기록된 변경 명령 암호화 로그가 아직 없습니다.</td></tr>`;
      return;
    }

    logs.forEach((entry) => {
      const ts = (entry.timestamp || "").replace("T", " ").slice(0, 19);
      const tr = document.createElement("tr");

      if (data.decrypted) {
        if (entry.decrypted) {
          const d = entry.decrypted;
          const wireBadge = d.wire_encrypted
            ? `<span class="badge badge-ok">🔒 패킷 암호화</span>`
            : `<span class="badge badge-info">암호문 저장</span>`;
          let summaryTitle = "";
          if (d.method && d.path) {
            summaryTitle = `<strong>${escapeHtml(d.method)} ${escapeHtml(d.path)}</strong> <span class="meta">(HTTP ${escapeHtml(d.status)} · ${escapeHtml(d.elapsed_ms)}ms)</span>`;
          } else if (Array.isArray(d.cmd)) {
            summaryTitle = `<code>${escapeHtml(d.cmd.join(" "))}</code> <span class="meta">(rc=${escapeHtml(d.rc)})</span>`;
          } else {
            summaryTitle = `<code>${escapeHtml(entry.id || "")}</code>`;
          }
          const prettyJson = escapeHtml(JSON.stringify(d, null, 2));
          tr.innerHTML = `
            <td>${escapeHtml(ts)}</td>
            <td><code>${escapeHtml(entry.event)}</code></td>
            <td>${wireBadge}</td>
            <td>
              <div>${summaryTitle}</div>
              <pre class="code-inline-box">${prettyJson}</pre>
              <details style="margin-top: 4px;">
                <summary class="meta" style="cursor: pointer;">Agent 저장 원본 암호문(enc) 보기</summary>
                <div class="enc-token-preview">${escapeHtml(entry.enc)}</div>
              </details>
            </td>
          `;
        } else {
          tr.innerHTML = `
            <td>${escapeHtml(ts)}</td>
            <td><code>${escapeHtml(entry.event)}</code></td>
            <td><span class="badge badge-err">복호화 실패</span></td>
            <td>
              <div style="color: #f87171;">${escapeHtml(entry.decrypt_error || "알 수 없는 오류")}</div>
              <div class="enc-token-preview">${escapeHtml(entry.enc)}</div>
            </td>
          `;
        }
      } else {
        tr.innerHTML = `
          <td>${escapeHtml(ts)}</td>
          <td><code>${escapeHtml(entry.event)}</code></td>
          <td><span class="badge badge-warn">🔒 암호문 원문</span></td>
          <td>
            <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 10px;">
              <div class="enc-token-preview">${escapeHtml(entry.enc)}</div>
              <button type="button" class="btn btn-sm btn-primary btn-decrypt-one" style="white-space: nowrap;">즉시 복호화</button>
            </div>
            <div class="single-decrypt-slot"></div>
          </td>
        `;
        const oneBtn = tr.querySelector(".btn-decrypt-one");
        const slot = tr.querySelector(".single-decrypt-slot");
        oneBtn.onclick = async () => {
          try {
            const decRes = await api(`/api/servers/${activeServerId}/agent-logs/decrypt`, {
              method: "POST",
              body: JSON.stringify({ lines: [entry.enc] }),
            });
            const first = decRes.results?.[0];
            if (first && first.decrypted) {
              slot.innerHTML = `<pre class="code-inline-box">${escapeHtml(JSON.stringify(first.decrypted, null, 2))}</pre>`;
            } else {
              slot.innerHTML = `<div style="color: #f87171; margin-top: 6px;">${escapeHtml(first?.error || "복호화 실패")}</div>`;
            }
          } catch (err) {
            toast(`복호화 실패: ${err.message}`, "err");
          }
        };
      }
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" style="color: #f87171;">Agent 로그 조회 실패: ${escapeHtml(err.message)}</td></tr>`;
  }
}

document.getElementById("manual-decrypt-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!activeServerId) {
    toast("먼저 좌측에서 서버(복호화 키 기준)를 선택하세요.", "err");
    return;
  }
  const rawText = document.getElementById("manual-decrypt-input").value;
  const lines = rawText.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return;

  const outBox = document.getElementById("manual-decrypt-output");
  outBox.innerHTML = `<span class="meta">복호화 중...</span>`;
  try {
    const res = await api(`/api/servers/${activeServerId}/agent-logs/decrypt`, {
      method: "POST",
      body: JSON.stringify({ lines }),
    });
    outBox.innerHTML = "";
    (res.results || []).forEach((item, idx) => {
      const block = document.createElement("div");
      if (item.decrypted) {
        block.innerHTML = `
          <div><span class="badge badge-ok">#${idx + 1} 복호화 성공</span></div>
          <pre class="code-inline-box">${escapeHtml(JSON.stringify(item.decrypted, null, 2))}</pre>
        `;
      } else {
        block.innerHTML = `
          <div><span class="badge badge-err">#${idx + 1} 실패</span> <span class="meta">${escapeHtml(item.error)}</span></div>
          <div class="enc-token-preview">${escapeHtml(item.raw)}</div>
        `;
      }
      outBox.appendChild(block);
    });
  } catch (err) {
    outBox.innerHTML = `<span style="color: #f87171;">복호화 요청 실패: ${escapeHtml(err.message)}</span>`;
  }
});

async function loadControllerPlainLogs() {
  const pre = document.getElementById("controller-plain-logs");
  try {
    const res = await api("/api/controller-logs?limit=100");
    const lines = res.logs || [];
    pre.textContent = lines.length > 0 ? lines.join("\n") : "기록된 Controller 평문 전송 로그가 없습니다.";
  } catch (err) {
    pre.textContent = `Controller 로그 조회 실패: ${err.message}`;
  }
}

// Server Add / Edit Modal
function openServerModal(srv = null) {
  const isEdit = Boolean(srv);
  document.getElementById("srv-modal-title").textContent = isEdit
    ? `관리 서버 정보 수정 (${srv.name})`
    : "새 리눅스 에이전트 서버 등록";
  document.getElementById("edit-srv-id").value = isEdit ? srv.id : "";
  document.getElementById("new-srv-name").value = isEdit ? srv.name : "";
  document.getElementById("new-srv-url").value = isEdit ? srv.url : "";
  document.getElementById("new-srv-group").value = isEdit ? (srv.group || "production") : "production";
  document.getElementById("new-srv-ports").value = isEdit && Array.isArray(srv.protected_ports)
    ? srv.protected_ports.join(", ")
    : "";

  const tokenInput = document.getElementById("new-srv-token");
  const tokenLabel = document.getElementById("srv-token-label");
  const tokenHint = document.getElementById("srv-token-hint");
  if (isEdit) {
    tokenLabel.textContent = "Agent Token (변경할 때만 입력)";
    tokenInput.value = "";
    tokenInput.placeholder = "비워두면 기존에 저장된 토큰 그대로 유지";
    tokenInput.required = false;
    tokenHint.textContent = "IP나 포트, 별칭만 수정할 경우 토큰 칸은 비워두세요.";
  } else {
    tokenLabel.textContent = "Agent Token";
    tokenInput.value = "dev-agent-token";
    tokenInput.placeholder = "";
    tokenInput.required = true;
    tokenHint.textContent = "";
  }

  document.getElementById("srv-submit-btn").textContent = isEdit ? "수정 저장" : "등록";
  document.getElementById("add-server-modal").classList.remove("hidden");
}

function openAddServerModal() {
  openServerModal(null);
}

function openEditActiveServerModal() {
  if (!activeServerId) {
    toast("먼저 좌측에서 수정할 서버를 선택하세요.", "err");
    return;
  }
  const srv = servers.find((s) => s.id === activeServerId);
  if (srv) openServerModal(srv);
}

function editServerFromList(event, serverId) {
  event.stopPropagation();
  const srv = servers.find((s) => s.id === serverId);
  if (srv) openServerModal(srv);
}

function closeAddServerModal() {
  document.getElementById("add-server-modal").classList.add("hidden");
}

document.getElementById("add-server-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const editId = document.getElementById("edit-srv-id").value.trim();
  const rawPorts = document.getElementById("new-srv-ports").value.trim();
  const parsedPorts = rawPorts
    ? rawPorts.split(",").map((p) => parseInt(p.trim(), 10)).filter((p) => p >= 1 && p <= 65535)
    : null;
  const tokenVal = document.getElementById("new-srv-token").value;

  try {
    if (editId) {
      const payload = {
        name: document.getElementById("new-srv-name").value.trim(),
        url: document.getElementById("new-srv-url").value.trim(),
        group: document.getElementById("new-srv-group").value.trim() || "default",
        protected_ports: parsedPorts,
      };
      if (tokenVal && tokenVal.trim()) {
        payload.token = tokenVal.trim();
      }
      await api(`/api/servers/${editId}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
      });
      closeAddServerModal();
      activeServerId = editId;
      toast("서버 정보가 수정되었습니다.", "ok");
      await loadServers(true);
    } else {
      const created = await api("/api/servers", {
        method: "POST",
        body: JSON.stringify({
          name: document.getElementById("new-srv-name").value.trim(),
          url: document.getElementById("new-srv-url").value.trim(),
          token: tokenVal,
          group: document.getElementById("new-srv-group").value.trim() || "default",
          protected_ports: parsedPorts,
        }),
      });
      closeAddServerModal();
      activeServerId = created.id;
      toast("새 서버가 등록되었습니다.", "ok");
      await loadServers(true);
    }
  } catch (err) {
    toast(`서버 저장 실패: ${err.message}`, "err");
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
