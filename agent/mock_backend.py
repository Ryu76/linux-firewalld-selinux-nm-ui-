import copy
from typing import Any

from agent.schemas import (
    FirewallControlRequest,
    FirewallForwardPortRequest,
    FirewallIcmpRequest,
    FirewallInterfaceRequest,
    FirewallMasqueradeRequest,
    FirewallPortRequest,
    FirewallRichRuleRequest,
    FirewallServiceRequest,
    FirewallSourceRequest,
    NetworkIPv4Request,
    SELinuxBooleanRequest,
    SELinuxModeRequest,
    SELinuxPortRequest,
)


class MockLinuxBackend:
    """Stateful in-memory Linux simulator for Windows/macOS development & testing."""

    mode_label = "mock-simulator"

    def __init__(self, hostname: str = "rocky9-web-01") -> None:
        self._state: dict[str, Any] = {
            "mode": self.mode_label,
            "hostname": hostname,
            "os": "Rocky Linux 9.4 (Simulated)",
            "listening_ports": [
                {"protocol": "tcp", "bind_ip": "0.0.0.0", "port": 22, "process": "sshd", "external_exposed": True},
                {"protocol": "tcp", "bind_ip": "0.0.0.0", "port": 80, "process": "nginx", "external_exposed": True},
                {"protocol": "tcp", "bind_ip": "0.0.0.0", "port": 8080, "process": "uvicorn", "external_exposed": True},
                {"protocol": "tcp", "bind_ip": "127.0.0.1", "port": 5432, "process": "postgres", "external_exposed": False},
            ],
            "firewall": {
                "running": True,
                "default_zone": "public",
                "panic_mode": False,
                "available_services": [
                    "cockpit", "dhcpv6-client", "dns", "ftp", "http", "https",
                    "mysql", "postgresql", "samba", "ssh", "vnc-server",
                ],
                "available_icmptypes": [
                    "address-unreachable", "bad-header", "communication-prohibited",
                    "destination-unreachable", "echo-reply", "echo-request",
                    "fragmentation-needed", "host-prohibited", "host-redirect",
                    "host-unreachable", "neighbour-advertisement", "neighbour-solicitation",
                    "network-prohibited", "network-redirect", "network-unreachable",
                    "packet-too-big", "parameter-problem", "port-unreachable",
                    "redirect", "router-advertisement", "router-solicitation",
                    "source-quench", "time-exceeded", "timestamp-reply", "timestamp-request",
                ],
                "service_ports": {
                    "cockpit": ["9090/tcp"],
                    "dhcpv6-client": ["546/udp"],
                    "dns": ["53/tcp", "53/udp"],
                    "ftp": ["21/tcp"],
                    "http": ["80/tcp"],
                    "https": ["443/tcp"],
                    "mysql": ["3306/tcp"],
                    "postgresql": ["5432/tcp"],
                    "samba": ["137/udp", "138/udp", "139/tcp", "445/tcp"],
                    "ssh": ["22/tcp"],
                    "vnc-server": ["5900-5903/tcp"],
                },
                "zones": {
                    "public": {
                        "target": "default",
                        "interfaces": ["ens160"],
                        "sources": [],
                        "services": ["cockpit", "dhcpv6-client", "ssh"],
                        "ports": ["22/tcp", "80/tcp"],
                        "protocols": [],
                        "masquerade": False,
                        "forward_ports": [],
                        "source_ports": [],
                        "icmp_blocks": [],
                        "rich_rules": [
                            'rule family="ipv4" source address="192.168.10.0/24" port port="8080" protocol="tcp" accept'
                        ],
                    },
                    "trusted": {
                        "target": "ACCEPT",
                        "interfaces": [],
                        "sources": [],
                        "services": [],
                        "ports": [],
                        "protocols": [],
                        "masquerade": False,
                        "forward_ports": [],
                        "source_ports": [],
                        "icmp_blocks": [],
                        "rich_rules": [],
                    },
                    "dmz": {
                        "target": "default",
                        "interfaces": [],
                        "sources": [],
                        "services": ["ssh"],
                        "ports": [],
                        "protocols": [],
                        "masquerade": False,
                        "forward_ports": [],
                        "source_ports": [],
                        "icmp_blocks": [],
                        "rich_rules": [],
                    },
                    "drop": {
                        "target": "DROP",
                        "interfaces": [],
                        "sources": [],
                        "services": [],
                        "ports": [],
                        "protocols": [],
                        "masquerade": False,
                        "forward_ports": [],
                        "source_ports": [],
                        "icmp_blocks": [],
                        "rich_rules": [],
                    },
                },
            },
            "selinux": {
                "mode": "Enforcing",
                "booleans": {
                    "httpd_can_network_connect": False,
                    "httpd_can_network_connect_db": False,
                },
                "custom_ports": [
                    {"port_type": "http_port_t", "protocol": "tcp", "ports": "80, 443, 8008"},
                ],
            },
            "network": [
                {
                    "connection": "ens160",
                    "device": "ens160",
                    "type": "802-3-ethernet",
                    "state": "activated",
                    "method": "manual",
                    "address": "192.168.10.50/24",
                    "gateway": "192.168.10.1",
                    "dns": "8.8.8.8",
                }
            ],
        }

    def get_status(self) -> dict[str, Any]:
        return copy.deepcopy(self._state)

    def _ensure_zone(self, zone: str) -> dict[str, Any]:
        return self._state["firewall"]["zones"].setdefault(
            zone,
            {
                "target": "default",
                "interfaces": [],
                "sources": [],
                "services": [],
                "ports": [],
                "protocols": [],
                "masquerade": False,
                "forward_ports": [],
                "source_ports": [],
                "icmp_blocks": [],
                "rich_rules": [],
            },
        )

    def manage_firewall_port(self, req: FirewallPortRequest) -> dict[str, Any]:
        zone_cfg = self._ensure_zone(req.zone)
        port_spec = f"{req.port}/{req.protocol}"
        if req.action == "add":
            if port_spec not in zone_cfg["ports"]:
                zone_cfg["ports"].append(port_spec)
        else:
            if port_spec not in zone_cfg["ports"]:
                raise RuntimeError(f"Port {port_spec} is not open in zone {req.zone}")
            zone_cfg["ports"].remove(port_spec)
        return {"ok": True, "detail": f"[MOCK] {req.action} {port_spec} in zone {req.zone}"}

    def manage_firewall_rich_rule(self, req: FirewallRichRuleRequest) -> dict[str, Any]:
        zone_cfg = self._ensure_zone(req.zone)
        rule = (
            f'rule family="ipv4" source address="{req.source_ip}" '
            f'port port="{req.port}" protocol="{req.protocol}" {req.rule_action}'
        )
        if req.action == "add":
            if rule not in zone_cfg["rich_rules"]:
                zone_cfg["rich_rules"].append(rule)
        else:
            if rule not in zone_cfg["rich_rules"]:
                raise RuntimeError("Rich rule not found")
            zone_cfg["rich_rules"].remove(rule)
        return {"ok": True, "detail": f"[MOCK] {req.action} rich-rule"}

    def manage_firewall_service(self, req: FirewallServiceRequest) -> dict[str, Any]:
        zone_cfg = self._ensure_zone(req.zone)
        if req.action == "add":
            if req.service not in zone_cfg["services"]:
                zone_cfg["services"].append(req.service)
        else:
            if req.service not in zone_cfg["services"]:
                raise RuntimeError(f"Service {req.service} not enabled in zone {req.zone}")
            zone_cfg["services"].remove(req.service)
        return {"ok": True, "detail": f"[MOCK] {req.action} service {req.service} in zone {req.zone}"}

    def manage_firewall_masquerade(self, req: FirewallMasqueradeRequest) -> dict[str, Any]:
        zone_cfg = self._ensure_zone(req.zone)
        zone_cfg["masquerade"] = req.enabled
        return {"ok": True, "detail": f"[MOCK] masquerade={'on' if req.enabled else 'off'} in zone {req.zone}"}

    def manage_firewall_forward_port(self, req: FirewallForwardPortRequest) -> dict[str, Any]:
        zone_cfg = self._ensure_zone(req.zone)
        spec = f"port={req.port}:proto={req.protocol}:toport={req.to_port}"
        if req.to_addr:
            spec += f":toaddr={req.to_addr}"
        if req.action == "add":
            if spec not in zone_cfg["forward_ports"]:
                zone_cfg["forward_ports"].append(spec)
        else:
            if spec not in zone_cfg["forward_ports"]:
                raise RuntimeError(f"Forward port {spec} not found")
            zone_cfg["forward_ports"].remove(spec)
        return {"ok": True, "detail": f"[MOCK] {req.action} forward-port {spec}"}

    def manage_firewall_source(self, req: FirewallSourceRequest) -> dict[str, Any]:
        zone_cfg = self._ensure_zone(req.zone)
        if req.action == "add":
            if req.source not in zone_cfg["sources"]:
                zone_cfg["sources"].append(req.source)
        else:
            if req.source not in zone_cfg["sources"]:
                raise RuntimeError(f"Source {req.source} not found")
            zone_cfg["sources"].remove(req.source)
        return {"ok": True, "detail": f"[MOCK] {req.action} source {req.source} in zone {req.zone}"}

    def manage_firewall_interface(self, req: FirewallInterfaceRequest) -> dict[str, Any]:
        for z in self._state["firewall"]["zones"].values():
            if req.interface in z["interfaces"]:
                z["interfaces"].remove(req.interface)
        if req.action == "change":
            self._ensure_zone(req.zone)["interfaces"].append(req.interface)
        return {"ok": True, "detail": f"[MOCK] {req.action} interface {req.interface} in zone {req.zone}"}

    def manage_firewall_icmp(self, req: FirewallIcmpRequest) -> dict[str, Any]:
        zone_cfg = self._ensure_zone(req.zone)
        if req.action == "add":
            if req.icmp_type not in zone_cfg["icmp_blocks"]:
                zone_cfg["icmp_blocks"].append(req.icmp_type)
        else:
            if req.icmp_type not in zone_cfg["icmp_blocks"]:
                raise RuntimeError(f"ICMP block {req.icmp_type} not found")
            zone_cfg["icmp_blocks"].remove(req.icmp_type)
        return {"ok": True, "detail": f"[MOCK] {req.action} icmp-block {req.icmp_type}"}

    def control_firewall(self, req: FirewallControlRequest) -> dict[str, Any]:
        if req.command == "set-default-zone":
            if not req.zone:
                raise RuntimeError("zone is required")
            self._ensure_zone(req.zone)
            self._state["firewall"]["default_zone"] = req.zone
        elif req.command == "panic-on":
            self._state["firewall"]["panic_mode"] = True
        elif req.command == "panic-off":
            self._state["firewall"]["panic_mode"] = False
        return {"ok": True, "detail": f"[MOCK] Executed firewall control: {req.command}"}

    def set_selinux_mode(self, req: SELinuxModeRequest) -> dict[str, Any]:
        self._state["selinux"]["mode"] = req.mode
        return {"ok": True, "detail": f"[MOCK] SELinux mode set to {req.mode}"}

    def manage_selinux_port(self, req: SELinuxPortRequest) -> dict[str, Any]:
        custom = self._state["selinux"]["custom_ports"]
        if req.action == "add":
            custom.append({"port_type": req.port_type, "protocol": req.protocol, "ports": str(req.port)})
        else:
            before = len(custom)
            self._state["selinux"]["custom_ports"] = [
                c for c in custom if not (c["port_type"] == req.port_type and str(req.port) in c["ports"])
            ]
            if len(self._state["selinux"]["custom_ports"]) == before:
                raise RuntimeError(f"SELinux port {req.port} ({req.port_type}) not found")
        return {"ok": True, "detail": f"[MOCK] semanage port {req.action} {req.port}/{req.protocol}"}

    def set_selinux_boolean(self, req: SELinuxBooleanRequest) -> dict[str, Any]:
        self._state["selinux"]["booleans"][req.name] = req.value
        return {"ok": True, "detail": f"[MOCK] Boolean {req.name} -> {'on' if req.value else 'off'}"}

    def configure_network_ipv4(self, req: NetworkIPv4Request) -> dict[str, Any]:
        for iface in self._state["network"]:
            if iface["connection"] == req.connection:
                iface["method"] = req.method
                if req.method == "manual":
                    if not req.address:
                        raise RuntimeError("address is required when method is manual")
                    iface["address"] = req.address
                    if req.gateway is not None:
                        iface["gateway"] = req.gateway
                    if req.dns is not None:
                        iface["dns"] = req.dns
                else:
                    iface["address"] = "192.168.10.123/24 (DHCP)"
                return {"ok": True, "detail": f"[MOCK] Updated {req.connection} ({req.method})"}
        raise RuntimeError(f"Connection '{req.connection}' not found")
