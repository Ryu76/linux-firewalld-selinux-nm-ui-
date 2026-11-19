import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def default_protected_ports(url: str) -> list[int]:
    ports = {22}
    parsed = urlparse(url)
    if parsed.port:
        ports.add(parsed.port)
    return sorted(ports)


class HubStore:
    """JSON-backed registry for managed Linux Agent servers and audit logs."""

    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = data_dir or (Path(__file__).resolve().parent / "data")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.servers_file = self.data_dir / "servers.json"
        self.audit_file = self.data_dir / "audit.jsonl"
        self._ensure_default_servers()

    def _ensure_default_servers(self) -> None:
        if not self.servers_file.exists():
            default = [
                {
                    "id": "srv-local-1",
                    "name": "rocky9-web-01 (Local Agent)",
                    "url": "http://127.0.0.1:9100",
                    "token": "dev-agent-token",
                    "group": "production",
                    "protected_ports": [22, 9100],
                }
            ]
            self.servers_file.write_text(json.dumps(default, indent=2, ensure_ascii=False), encoding="utf-8")

    def list_servers(self) -> list[dict[str, Any]]:
        try:
            return json.loads(self.servers_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def get_server(self, server_id: str) -> dict[str, Any] | None:
        for srv in self.list_servers():
            if srv["id"] == server_id:
                return srv
        return None

    def get_protected_ports(self, srv: dict[str, Any]) -> list[int]:
        if "protected_ports" in srv and isinstance(srv["protected_ports"], list):
            return sorted({int(p) for p in srv["protected_ports"] if 1 <= int(p) <= 65535})
        return default_protected_ports(srv.get("url", ""))

    def add_server(
        self,
        name: str,
        url: str,
        token: str,
        group: str = "default",
        protected_ports: list[int] | None = None,
    ) -> dict[str, Any]:
        servers = self.list_servers()
        ports = (
            sorted({int(p) for p in protected_ports if 1 <= int(p) <= 65535})
            if protected_ports is not None
            else default_protected_ports(url)
        )
        new_srv = {
            "id": f"srv-{uuid.uuid4().hex[:8]}",
            "name": name,
            "url": url.rstrip("/"),
            "token": token,
            "group": group,
            "protected_ports": ports,
        }
        servers.append(new_srv)
        self.servers_file.write_text(json.dumps(servers, indent=2, ensure_ascii=False), encoding="utf-8")
        return new_srv

    def update_protected_ports(self, server_id: str, ports: list[int]) -> dict[str, Any] | None:
        servers = self.list_servers()
        updated: dict[str, Any] | None = None
        clean_ports = sorted({int(p) for p in ports if 1 <= int(p) <= 65535})
        for srv in servers:
            if srv["id"] == server_id:
                srv["protected_ports"] = clean_ports
                updated = srv
                break
        if updated is None:
            return None
        self.servers_file.write_text(json.dumps(servers, indent=2, ensure_ascii=False), encoding="utf-8")
        return updated

    def remove_server(self, server_id: str) -> bool:
        servers = self.list_servers()
        filtered = [s for s in servers if s["id"] != server_id]
        if len(filtered) == len(servers):
            return False
        self.servers_file.write_text(json.dumps(filtered, indent=2, ensure_ascii=False), encoding="utf-8")
        return True

    def append_audit(
        self,
        server_id: str,
        server_name: str,
        action: str,
        payload: dict[str, Any],
        success: bool,
        detail: str,
    ) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "server_id": server_id,
            "server_name": server_name,
            "action": action,
            "payload": payload,
            "success": success,
            "detail": detail,
        }
        with self.audit_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def list_audit(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.audit_file.exists():
            return []
        lines = self.audit_file.read_text(encoding="utf-8").splitlines()
        entries: list[dict[str, Any]] = []
        for line in reversed(lines[-limit:]):
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries
