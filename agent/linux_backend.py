import platform
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional

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


def _run_cmd(args: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Execute a system command safely without shell interpolation."""
    try:
        proc = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out: {' '.join(args)}"


class LinuxBackend:
    """Real Linux backend using firewall-cmd, SELinux tools, nmcli, and ss."""

    mode_label = "live-linux"

    def __init__(self) -> None:
        self._cached_services: Optional[list[str]] = None
        self._cached_service_ports: Optional[dict[str, list[str]]] = None
        self._cached_icmptypes: Optional[list[str]] = None

    def get_status(self) -> dict[str, Any]:
        return {
            "mode": self.mode_label,
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "listening_ports": self._get_listening_ports(),
            "firewall": self._get_firewall_status(),
            "selinux": self._get_selinux_status(),
            "network": self._get_network_status(),
        }

    def _get_listening_ports(self) -> list[dict[str, Any]]:
        rc, out, _ = _run_cmd(["ss", "-tulnpH"])
        if rc != 0:
            return []
        ports: list[dict[str, Any]] = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local_addr = parts[4]
            proc_info = parts[6] if len(parts) > 6 else ""
            match = re.search(r"^(.*):(\d+)$", local_addr)
            if not match:
                continue
            bind_ip, port_str = match.group(1), match.group(2)
            proc_match = re.search(r'"([^"]+)"', proc_info)
            ports.append(
                {
                    "protocol": proto,
                    "bind_ip": bind_ip,
                    "port": int(port_str),
                    "process": proc_match.group(1) if proc_match else "unknown",
                    "external_exposed": bind_ip in ("0.0.0.0", "*", "::", "[::]"),
                }
            )
        return ports

    def _get_firewall_status(self) -> dict[str, Any]:
        rc_state, state_out, _ = _run_cmd(["firewall-cmd", "--state"])
        running = rc_state == 0 and state_out == "running"
        if not running:
            return {
                "running": False,
                "default_zone": "unknown",
                "panic_mode": False,
                "available_services": [],
                "zones": {},
            }

        _, default_zone, _ = _run_cmd(["firewall-cmd", "--get-default-zone"])
        rc_panic, _, _ = _run_cmd(["firewall-cmd", "--query-panic"])
        panic_mode = rc_panic == 0

        if self._cached_services is None:
            rc_svc, svc_out, _ = _run_cmd(["firewall-cmd", "--get-services"])
            if rc_svc == 0 and svc_out:
                self._cached_services = sorted(svc_out.split())
            else:
                self._cached_services = []

        if self._cached_service_ports is None:
            self._cached_service_ports = self._load_service_ports()

        if self._cached_icmptypes is None:
            rc_icmp, icmp_out, _ = _run_cmd(["firewall-cmd", "--get-icmptypes"])
            if rc_icmp == 0 and icmp_out:
                self._cached_icmptypes = sorted(icmp_out.split())
            else:
                self._cached_icmptypes = []

        _, zones_out, _ = _run_cmd(["firewall-cmd", "--list-all-zones"])
        zones = self._parse_all_zones(zones_out)
        return {
            "running": True,
            "default_zone": default_zone or "public",
            "panic_mode": panic_mode,
            "available_services": self._cached_services,
            "service_ports": self._cached_service_ports,
            "available_icmptypes": self._cached_icmptypes,
            "zones": zones,
        }

    @staticmethod
    def _load_service_ports() -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {}
        for base_dir in (Path("/usr/lib/firewalld/services"), Path("/etc/firewalld/services")):
            if not base_dir.is_dir():
                continue
            for xml_file in base_dir.glob("*.xml"):
                try:
                    root = ET.parse(xml_file).getroot()
                    ports: list[str] = []
                    for elem in root.findall("port"):
                        p = elem.attrib.get("port")
                        proto = elem.attrib.get("protocol", "tcp")
                        if p:
                            ports.append(f"{p}/{proto}")
                    mapping[xml_file.stem] = ports
                except ET.ParseError:
                    continue
        return mapping

    @staticmethod
    def _parse_all_zones(output: str) -> dict[str, Any]:
        zones: dict[str, Any] = {}
        current_zone: Optional[str] = None
        lines_buf: list[str] = []

        for line in output.splitlines():
            if line and not line.startswith(" ") and not line.startswith("\t"):
                if current_zone is not None:
                    zones[current_zone] = LinuxBackend._parse_firewall_zone("\n".join(lines_buf))
                current_zone = line.split()[0].strip()
                lines_buf = []
            elif current_zone is not None:
                lines_buf.append(line)

        if current_zone is not None:
            zones[current_zone] = LinuxBackend._parse_firewall_zone("\n".join(lines_buf))
        return zones

    @staticmethod
    def _parse_firewall_zone(output: str) -> dict[str, Any]:
        target = "default"
        interfaces: list[str] = []
        sources: list[str] = []
        services: list[str] = []
        ports: list[str] = []
        protocols: list[str] = []
        forward_ports: list[str] = []
        source_ports: list[str] = []
        icmp_blocks: list[str] = []
        masquerade = False
        rich_rules: list[str] = []
        section = ""

        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("target:"):
                section = ""
                target = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("interfaces:"):
                section = ""
                interfaces = stripped.split(":", 1)[1].strip().split()
            elif stripped.startswith("sources:"):
                section = ""
                sources = stripped.split(":", 1)[1].strip().split()
            elif stripped.startswith("services:"):
                section = ""
                services = stripped.split(":", 1)[1].strip().split()
            elif stripped.startswith("ports:"):
                section = ""
                ports = stripped.split(":", 1)[1].strip().split()
            elif stripped.startswith("protocols:"):
                section = ""
                protocols = stripped.split(":", 1)[1].strip().split()
            elif stripped.startswith("masquerade:"):
                section = ""
                masquerade = stripped.split(":", 1)[1].strip() == "yes"
            elif stripped.startswith("forward-ports:"):
                section = "forward-ports"
                rest = stripped.split(":", 1)[1].strip()
                if rest:
                    forward_ports.append(rest)
            elif stripped.startswith("source-ports:"):
                section = ""
                source_ports = stripped.split(":", 1)[1].strip().split()
            elif stripped.startswith("icmp-blocks:"):
                section = ""
                icmp_blocks = stripped.split(":", 1)[1].strip().split()
            elif stripped.startswith("rich rules:"):
                section = "rich"
            elif section == "rich" and stripped:
                rich_rules.append(stripped)
            elif section == "forward-ports" and stripped:
                forward_ports.append(stripped)

        return {
            "target": target,
            "interfaces": interfaces,
            "sources": sources,
            "services": services,
            "ports": ports,
            "protocols": protocols,
            "masquerade": masquerade,
            "forward_ports": forward_ports,
            "source_ports": source_ports,
            "icmp_blocks": icmp_blocks,
            "rich_rules": rich_rules,
        }

    def _get_selinux_status(self) -> dict[str, Any]:
        rc, mode_out, _ = _run_cmd(["getenforce"])
        mode = mode_out if rc == 0 else "Unavailable"

        booleans: dict[str, bool] = {}
        rc_b, bool_out, _ = _run_cmd(["getsebool", "httpd_can_network_connect", "httpd_can_network_connect_db"])
        if rc_b == 0:
            for line in bool_out.splitlines():
                if "-->" in line:
                    k, v = line.split("-->", 1)
                    booleans[k.strip()] = v.strip() == "on"

        custom_ports: list[dict[str, Any]] = []
        rc_p, port_out, _ = _run_cmd(["semanage", "port", "-l", "-C"])
        if rc_p == 0:
            for line in port_out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    custom_ports.append(
                        {"port_type": parts[0], "protocol": parts[1], "ports": " ".join(parts[2:])}
                    )

        return {
            "mode": mode,
            "booleans": booleans,
            "custom_ports": custom_ports,
        }

    def _get_network_status(self) -> list[dict[str, Any]]:
        rc, out, _ = _run_cmd(["nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE,STATE", "con", "show"])
        if rc != 0:
            return []
        interfaces: list[dict[str, Any]] = []
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) < 5:
                continue
            name, _, con_type, device, state = parts[:5]
            if con_type == "loopback":
                continue
            ip4, gw4, dns4, method = "", "", "", ""
            _, detail, _ = _run_cmd(
                ["nmcli", "-t", "-f", "ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns", "con", "show", name]
            )
            for dline in detail.splitlines():
                if dline.startswith("ipv4.method:"):
                    method = dline.split(":", 1)[1]
                elif dline.startswith("ipv4.addresses:"):
                    ip4 = dline.split(":", 1)[1]
                elif dline.startswith("ipv4.gateway:"):
                    gw4 = dline.split(":", 1)[1]
                elif dline.startswith("ipv4.dns:"):
                    dns4 = dline.split(":", 1)[1]
            interfaces.append(
                {
                    "connection": name,
                    "device": device or "--",
                    "type": con_type,
                    "state": state or "inactive",
                    "method": method,
                    "address": ip4,
                    "gateway": gw4,
                    "dns": dns4,
                }
            )
        return interfaces

    def manage_firewall_port(self, req: FirewallPortRequest) -> dict[str, Any]:
        flag = "--add-port" if req.action == "add" else "--remove-port"
        port_spec = f"{req.port}/{req.protocol}"
        cmd = ["firewall-cmd", f"--zone={req.zone}"]
        if req.permanent:
            cmd.append("--permanent")
        cmd.append(f"{flag}={port_spec}")
        rc, out, err = _run_cmd(cmd)
        if rc != 0:
            raise RuntimeError(err or out or "firewall-cmd failed")
        if req.permanent:
            rc_r, out_r, err_r = _run_cmd(["firewall-cmd", "--reload"])
            if rc_r != 0:
                raise RuntimeError(err_r or out_r or "firewall-cmd --reload failed")
        return {"ok": True, "detail": f"{req.action} {port_spec} in zone {req.zone}"}

    def manage_firewall_rich_rule(self, req: FirewallRichRuleRequest) -> dict[str, Any]:
        rule = (
            f'rule family="ipv4" source address="{req.source_ip}" '
            f'port port="{req.port}" protocol="{req.protocol}" {req.rule_action}'
        )
        flag = "--add-rich-rule" if req.action == "add" else "--remove-rich-rule"
        cmd = ["firewall-cmd", f"--zone={req.zone}"]
        if req.permanent:
            cmd.append("--permanent")
        cmd.append(f"{flag}={rule}")
        rc, out, err = _run_cmd(cmd)
        if rc != 0:
            raise RuntimeError(err or out or "firewall-cmd rich-rule failed")
        if req.permanent:
            rc_r, out_r, err_r = _run_cmd(["firewall-cmd", "--reload"])
            if rc_r != 0:
                raise RuntimeError(err_r or out_r or "firewall-cmd --reload failed")
        return {"ok": True, "detail": f"{req.action} rich-rule: {rule}"}

    def _run_fw_zone_cmd(self, zone: str, permanent: bool, flag_arg: str, detail: str) -> dict[str, Any]:
        cmd = ["firewall-cmd", f"--zone={zone}"]
        if permanent:
            cmd.append("--permanent")
        cmd.append(flag_arg)
        rc, out, err = _run_cmd(cmd)
        if rc != 0:
            raise RuntimeError(err or out or "firewall-cmd failed")
        if permanent:
            rc_r, out_r, err_r = _run_cmd(["firewall-cmd", "--reload"])
            if rc_r != 0:
                raise RuntimeError(err_r or out_r or "firewall-cmd --reload failed")
        return {"ok": True, "detail": detail}

    def manage_firewall_service(self, req: FirewallServiceRequest) -> dict[str, Any]:
        flag = "--add-service" if req.action == "add" else "--remove-service"
        return self._run_fw_zone_cmd(
            req.zone, req.permanent, f"{flag}={req.service}", f"{req.action} service {req.service} in zone {req.zone}"
        )

    def manage_firewall_masquerade(self, req: FirewallMasqueradeRequest) -> dict[str, Any]:
        flag = "--add-masquerade" if req.enabled else "--remove-masquerade"
        return self._run_fw_zone_cmd(
            req.zone, req.permanent, flag, f"masquerade={'on' if req.enabled else 'off'} in zone {req.zone}"
        )

    def manage_firewall_forward_port(self, req: FirewallForwardPortRequest) -> dict[str, Any]:
        spec = f"port={req.port}:proto={req.protocol}:toport={req.to_port}"
        if req.to_addr:
            spec += f":toaddr={req.to_addr}"
        flag = "--add-forward-port" if req.action == "add" else "--remove-forward-port"
        return self._run_fw_zone_cmd(
            req.zone, req.permanent, f"{flag}={spec}", f"{req.action} forward-port {spec} in zone {req.zone}"
        )

    def manage_firewall_source(self, req: FirewallSourceRequest) -> dict[str, Any]:
        flag = "--add-source" if req.action == "add" else "--remove-source"
        return self._run_fw_zone_cmd(
            req.zone, req.permanent, f"{flag}={req.source}", f"{req.action} source {req.source} in zone {req.zone}"
        )

    def manage_firewall_interface(self, req: FirewallInterfaceRequest) -> dict[str, Any]:
        flag = "--change-interface" if req.action == "change" else "--remove-interface"
        return self._run_fw_zone_cmd(
            req.zone, req.permanent, f"{flag}={req.interface}", f"{req.action} interface {req.interface} in zone {req.zone}"
        )

    def manage_firewall_icmp(self, req: FirewallIcmpRequest) -> dict[str, Any]:
        flag = "--add-icmp-block" if req.action == "add" else "--remove-icmp-block"
        return self._run_fw_zone_cmd(
            req.zone, req.permanent, f"{flag}={req.icmp_type}", f"{req.action} icmp-block {req.icmp_type} in zone {req.zone}"
        )

    def control_firewall(self, req: FirewallControlRequest) -> dict[str, Any]:
        if req.command == "reload":
            cmd = ["firewall-cmd", "--reload"]
        elif req.command == "runtime-to-permanent":
            cmd = ["firewall-cmd", "--runtime-to-permanent"]
        elif req.command == "set-default-zone":
            if not req.zone:
                raise RuntimeError("zone is required for set-default-zone")
            cmd = ["firewall-cmd", f"--set-default-zone={req.zone}"]
        elif req.command == "panic-on":
            cmd = ["firewall-cmd", "--panic-on"]
        else:
            cmd = ["firewall-cmd", "--panic-off"]
        rc, out, err = _run_cmd(cmd)
        if rc != 0:
            raise RuntimeError(err or out or f"firewall-cmd {req.command} failed")
        return {"ok": True, "detail": f"Executed firewall control: {req.command}"}

    def set_selinux_mode(self, req: SELinuxModeRequest) -> dict[str, Any]:
        val = "1" if req.mode == "Enforcing" else "0"
        rc, out, err = _run_cmd(["setenforce", val])
        if rc != 0:
            raise RuntimeError(err or out or "setenforce failed")
        return {"ok": True, "detail": f"SELinux mode set to {req.mode}"}

    def manage_selinux_port(self, req: SELinuxPortRequest) -> dict[str, Any]:
        flag = "-a" if req.action == "add" else "-d"
        cmd = ["semanage", "port", flag, "-t", req.port_type, "-p", req.protocol, str(req.port)]
        rc, out, err = _run_cmd(cmd)
        if rc != 0:
            raise RuntimeError(err or out or "semanage port failed")
        return {"ok": True, "detail": f"semanage port {req.action} {req.port}/{req.protocol} ({req.port_type})"}

    def set_selinux_boolean(self, req: SELinuxBooleanRequest) -> dict[str, Any]:
        cmd = ["setsebool"]
        if req.persistent:
            cmd.append("-P")
        cmd.extend([req.name, "on" if req.value else "off"])
        rc, out, err = _run_cmd(cmd, timeout=20)
        if rc != 0:
            raise RuntimeError(err or out or "setsebool failed")
        return {"ok": True, "detail": f"Boolean {req.name} -> {'on' if req.value else 'off'}"}

    def configure_network_ipv4(self, req: NetworkIPv4Request) -> dict[str, Any]:
        cmd = ["nmcli", "con", "mod", req.connection, "ipv4.method", req.method]
        if req.method == "manual":
            if not req.address:
                raise RuntimeError("address is required when method is manual")
            cmd.extend(["ipv4.addresses", req.address])
            if req.gateway:
                cmd.extend(["ipv4.gateway", req.gateway])
            if req.dns:
                cmd.extend(["ipv4.dns", req.dns])
        rc, out, err = _run_cmd(cmd)
        if rc != 0:
            raise RuntimeError(err or out or "nmcli con mod failed")
        rc_up, out_up, err_up = _run_cmd(["nmcli", "con", "up", req.connection])
        if rc_up != 0:
            raise RuntimeError(err_up or out_up or "nmcli con up failed")
        return {"ok": True, "detail": f"Updated {req.connection} ({req.method}) and reactivated"}
