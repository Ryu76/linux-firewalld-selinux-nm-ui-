import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, select

from controller.db import DatabaseManager
from controller.models import AuditLog, ProcessLog, Server, WatchedProcess


def default_protected_ports(url: str) -> list[int]:
    ports = {22}
    parsed = urlparse(url)
    if parsed.port:
        ports.add(parsed.port)
    return sorted(ports)


def _normalize_ports(ports: list[int]) -> list[int]:
    return sorted({int(p) for p in ports if 1 <= int(p) <= 65535})


def _server_to_dict(srv: Server) -> dict[str, Any]:
    return {
        "id": srv.id,
        "name": srv.name,
        "url": srv.url,
        "token": srv.token,
        "group": srv.group,
        "protected_ports": list(srv.protected_ports or [22]),
    }


def _audit_to_dict(entry: AuditLog) -> dict[str, Any]:
    return {
        "id": entry.id,
        "timestamp": entry.timestamp.isoformat(),
        "server_id": entry.server_id,
        "server_name": entry.server_name,
        "action": entry.action,
        "payload": entry.payload,
        "success": entry.success,
        "detail": entry.detail,
    }


def _process_to_dict(proc: WatchedProcess) -> dict[str, Any]:
    return {
        "id": proc.id,
        "server_id": proc.server_id,
        "process_name": proc.process_name,
        "check_type": proc.check_type,
        "enabled": proc.enabled,
        "save_log": proc.save_log,
        "recovery_action": proc.recovery_action,
        "recovery_target": proc.recovery_target,
        "check_interval_sec": proc.check_interval_sec,
        "last_status": proc.last_status,
        "last_checked_at": proc.last_checked_at.isoformat() if proc.last_checked_at else None,
        "last_action_detail": proc.last_action_detail,
    }


def _process_log_to_dict(entry: ProcessLog) -> dict[str, Any]:
    return {
        "id": entry.id,
        "timestamp": entry.timestamp.isoformat(),
        "server_id": entry.server_id,
        "server_name": entry.server_name,
        "process_id": entry.process_id,
        "process_name": entry.process_name,
        "status": entry.status,
        "action_taken": entry.action_taken,
        "success": entry.success,
        "detail": entry.detail,
    }


def _parse_iso_datetime(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(raw)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


class HubStore:
    """PostgreSQL/SQLAlchemy async registry for managed Linux Agent servers and audit logs."""

    def __init__(self, db: DatabaseManager | None = None, data_dir: Path | None = None) -> None:
        self.db = db or DatabaseManager()
        self.data_dir = data_dir or (Path(__file__).resolve().parent / "data")
        self.servers_file = self.data_dir / "servers.json"
        self.audit_file = self.data_dir / "audit.jsonl"

    async def init(self) -> None:
        await self.db.init_schema()
        await self._migrate_or_seed()

    async def close(self) -> None:
        await self.db.dispose()

    async def _migrate_or_seed(self) -> None:
        async with self.db.session_factory() as session:
            srv_count = (await session.scalar(select(func.count()).select_from(Server))) or 0
            if srv_count == 0:
                if self.servers_file.exists():
                    try:
                        raw_servers = json.loads(self.servers_file.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        raw_servers = []
                    for item in raw_servers:
                        url = str(item.get("url", "")).rstrip("/")
                        ports = item.get("protected_ports")
                        clean_ports = _normalize_ports(ports) if isinstance(ports, list) else default_protected_ports(url)
                        session.add(
                            Server(
                                id=item.get("id") or f"srv-{uuid.uuid4().hex[:8]}",
                                name=item.get("name", "unknown"),
                                url=url,
                                token=item.get("token", ""),
                                group=item.get("group", "default"),
                                protected_ports=clean_ports,
                            )
                        )
                else:
                    session.add(
                        Server(
                            id="srv-local-1",
                            name="rocky9-web-01 (Local Agent)",
                            url="http://127.0.0.1:8754",
                            token="dev-agent-token",
                            group="production",
                            protected_ports=[22, 8754],
                        )
                    )

            audit_count = (await session.scalar(select(func.count()).select_from(AuditLog))) or 0
            if audit_count == 0 and self.audit_file.exists():
                try:
                    lines = self.audit_file.read_text(encoding="utf-8").splitlines()
                except OSError:
                    lines = []
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    session.add(
                        AuditLog(
                            timestamp=_parse_iso_datetime(item.get("timestamp")),
                            server_id=str(item.get("server_id", "")),
                            server_name=str(item.get("server_name", "")),
                            action=str(item.get("action", "")),
                            payload=item.get("payload") if isinstance(item.get("payload"), dict) else {},
                            success=bool(item.get("success", False)),
                            detail=str(item.get("detail", "")),
                        )
                    )
            await session.commit()

    def get_protected_ports(self, srv: dict[str, Any]) -> list[int]:
        if "protected_ports" in srv and isinstance(srv["protected_ports"], list):
            return _normalize_ports(srv["protected_ports"])
        return default_protected_ports(srv.get("url", ""))

    async def list_servers(self) -> list[dict[str, Any]]:
        async with self.db.session_factory() as session:
            result = await session.scalars(select(Server).order_by(Server.created_at.asc(), Server.id.asc()))
            return [_server_to_dict(srv) for srv in result.all()]

    async def get_server(self, server_id: str) -> dict[str, Any] | None:
        async with self.db.session_factory() as session:
            srv = await session.get(Server, server_id)
            return _server_to_dict(srv) if srv else None

    async def add_server(
        self,
        name: str,
        url: str,
        token: str,
        group: str = "default",
        protected_ports: list[int] | None = None,
    ) -> dict[str, Any]:
        clean_url = url.rstrip("/")
        ports = _normalize_ports(protected_ports) if protected_ports is not None else default_protected_ports(clean_url)
        new_srv = Server(
            id=f"srv-{uuid.uuid4().hex[:8]}",
            name=name,
            url=clean_url,
            token=token,
            group=group,
            protected_ports=ports,
        )
        async with self.db.session_factory() as session:
            session.add(new_srv)
            await session.commit()
            await session.refresh(new_srv)
            return _server_to_dict(new_srv)

    async def update_server(
        self,
        server_id: str,
        name: str | None = None,
        url: str | None = None,
        token: str | None = None,
        group: str | None = None,
        protected_ports: list[int] | None = None,
    ) -> dict[str, Any] | None:
        async with self.db.session_factory() as session:
            srv = await session.get(Server, server_id)
            if not srv:
                return None

            old_parsed = urlparse(srv.url)
            old_port = old_parsed.port

            if name is not None and name.strip():
                srv.name = name.strip()
            if url is not None and url.strip():
                srv.url = url.strip().rstrip("/")
            if token is not None and token.strip():
                srv.token = token.strip()
            if group is not None and group.strip():
                srv.group = group.strip()

            if protected_ports is not None:
                srv.protected_ports = _normalize_ports(protected_ports)
            elif url is not None and url.strip():
                new_port = urlparse(srv.url).port
                cur_ports = set(srv.protected_ports or [22])
                if old_port and old_port != 22 and old_port != new_port:
                    cur_ports.discard(old_port)
                if new_port:
                    cur_ports.add(new_port)
                srv.protected_ports = _normalize_ports(list(cur_ports))

            await session.commit()
            await session.refresh(srv)
            return _server_to_dict(srv)

    async def update_protected_ports(self, server_id: str, ports: list[int]) -> dict[str, Any] | None:
        clean_ports = _normalize_ports(ports)
        async with self.db.session_factory() as session:
            srv = await session.get(Server, server_id)
            if not srv:
                return None
            srv.protected_ports = clean_ports
            await session.commit()
            await session.refresh(srv)
            return _server_to_dict(srv)

    async def remove_server(self, server_id: str) -> bool:
        async with self.db.session_factory() as session:
            srv = await session.get(Server, server_id)
            if not srv:
                return False
            await session.delete(srv)
            await session.commit()
            return True

    async def append_audit(
        self,
        server_id: str,
        server_name: str,
        action: str,
        payload: dict[str, Any],
        success: bool,
        detail: str,
    ) -> None:
        entry = AuditLog(
            timestamp=datetime.now(timezone.utc),
            server_id=server_id,
            server_name=server_name,
            action=action,
            payload=payload,
            success=success,
            detail=detail,
        )
        async with self.db.session_factory() as session:
            session.add(entry)
            await session.commit()

    async def list_audit(
        self,
        limit: int = 50,
        server_id: str | None = None,
        action: str | None = None,
        success: bool | None = None,
    ) -> list[dict[str, Any]]:
        stmt = select(AuditLog)
        if server_id is not None:
            stmt = stmt.where(AuditLog.server_id == server_id)
        if action is not None:
            stmt = stmt.where(AuditLog.action == action)
        if success is not None:
            stmt = stmt.where(AuditLog.success == success)
        stmt = stmt.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).limit(max(1, min(limit, 500)))
        async with self.db.session_factory() as session:
            result = await session.scalars(stmt)
            return [_audit_to_dict(entry) for entry in result.all()]

    async def list_processes(
        self,
        server_id: str | None = None,
        enabled_only: bool = False,
    ) -> list[dict[str, Any]]:
        stmt = select(WatchedProcess)
        if server_id is not None:
            stmt = stmt.where(WatchedProcess.server_id == server_id)
        if enabled_only:
            stmt = stmt.where(WatchedProcess.enabled.is_(True))
        stmt = stmt.order_by(WatchedProcess.created_at.asc(), WatchedProcess.id.asc())
        async with self.db.session_factory() as session:
            result = await session.scalars(stmt)
            return [_process_to_dict(proc) for proc in result.all()]

    async def get_process(self, process_id: str) -> dict[str, Any] | None:
        async with self.db.session_factory() as session:
            proc = await session.get(WatchedProcess, process_id)
            return _process_to_dict(proc) if proc else None

    async def add_process(
        self,
        server_id: str,
        process_name: str,
        check_type: str = "process",
        enabled: bool = True,
        save_log: bool = True,
        recovery_action: str = "alert_only",
        recovery_target: str = "",
        check_interval_sec: int = 30,
    ) -> dict[str, Any]:
        proc = WatchedProcess(
            id=f"proc-{uuid.uuid4().hex[:8]}",
            server_id=server_id,
            process_name=process_name,
            check_type=check_type,
            enabled=enabled,
            save_log=save_log,
            recovery_action=recovery_action,
            recovery_target=recovery_target,
            check_interval_sec=max(5, check_interval_sec),
        )
        async with self.db.session_factory() as session:
            session.add(proc)
            await session.commit()
            await session.refresh(proc)
            return _process_to_dict(proc)

    async def update_process(self, process_id: str, **fields: Any) -> dict[str, Any] | None:
        allowed = {
            "process_name",
            "check_type",
            "enabled",
            "save_log",
            "recovery_action",
            "recovery_target",
            "check_interval_sec",
        }
        async with self.db.session_factory() as session:
            proc = await session.get(WatchedProcess, process_id)
            if not proc:
                return None
            for key, value in fields.items():
                if key in allowed and value is not None:
                    if key == "check_interval_sec":
                        value = max(5, int(value))
                    setattr(proc, key, value)
            await session.commit()
            await session.refresh(proc)
            return _process_to_dict(proc)

    async def remove_process(self, process_id: str) -> bool:
        async with self.db.session_factory() as session:
            proc = await session.get(WatchedProcess, process_id)
            if not proc:
                return False
            await session.delete(proc)
            await session.commit()
            return True

    async def update_process_status(
        self,
        process_id: str,
        status: str,
        action_detail: str = "",
        checked_at: datetime | None = None,
    ) -> None:
        async with self.db.session_factory() as session:
            proc = await session.get(WatchedProcess, process_id)
            if not proc:
                return
            proc.last_status = status
            proc.last_checked_at = checked_at or datetime.now(timezone.utc)
            proc.last_action_detail = action_detail
            await session.commit()

    async def append_process_log(
        self,
        server_id: str,
        server_name: str,
        process_id: str,
        process_name: str,
        status: str,
        action_taken: str,
        success: bool,
        detail: str,
    ) -> None:
        entry = ProcessLog(
            timestamp=datetime.now(timezone.utc),
            server_id=server_id,
            server_name=server_name,
            process_id=process_id,
            process_name=process_name,
            status=status,
            action_taken=action_taken,
            success=success,
            detail=detail,
        )
        async with self.db.session_factory() as session:
            session.add(entry)
            await session.commit()

    async def list_process_logs(
        self,
        limit: int = 100,
        server_id: str | None = None,
        process_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        stmt = select(ProcessLog)
        if server_id is not None:
            stmt = stmt.where(ProcessLog.server_id == server_id)
        if process_id is not None:
            stmt = stmt.where(ProcessLog.process_id == process_id)
        if status is not None:
            stmt = stmt.where(ProcessLog.status == status)
        stmt = stmt.order_by(ProcessLog.timestamp.desc(), ProcessLog.id.desc()).limit(max(1, min(limit, 500)))
        async with self.db.session_factory() as session:
            result = await session.scalars(stmt)
            return [_process_log_to_dict(entry) for entry in result.all()]
