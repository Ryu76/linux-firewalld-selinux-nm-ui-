import asyncio
import json
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from controller.agent_client import decrypt_agent_log_entry, decrypt_raw_log_line, send_encrypted_command
from controller.logger import get_controller_logger, list_controller_plain_logs
from controller.monitor import ProcessMonitor
from controller.store import HubStore

logger = get_controller_logger("controller.api")
http_transport: httpx.AsyncBaseTransport | None = None


def _make_http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=http_transport)

ALLOWED_ACTIONS = {
    "firewall/port",
    "firewall/rich-rule",
    "firewall/service",
    "firewall/masquerade",
    "firewall/forward-port",
    "firewall/source",
    "firewall/interface",
    "firewall/icmp",
    "firewall/control",
    "selinux/mode",
    "selinux/port",
    "selinux/boolean",
    "network/ipv4",
}

STATIC_DIR = Path(__file__).resolve().parent / "static"

store = HubStore()
monitor = ProcessMonitor(store)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await store.init()
    monitor.start()
    try:
        yield
    finally:
        await monitor.stop()
        await store.close()


app = FastAPI(
    title="Linux Access Control Hub (Controller)",
    description="Multi-server web dashboard controller for Linux firewalld, SELinux, and nmcli agents",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class ServerCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    url: str = Field(min_length=7, max_length=255)
    token: str = Field(min_length=1, max_length=255)
    group: str = Field(default="default", max_length=40)
    protected_ports: list[int] | None = None


class ServerUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    url: str | None = Field(default=None, min_length=7, max_length=255)
    token: str | None = Field(default=None, max_length=255)
    group: str | None = Field(default=None, max_length=40)
    protected_ports: list[int] | None = None


class ProtectedPortsUpdateRequest(BaseModel):
    ports: list[int] = Field(default_factory=list)


SAFE_PROC_NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{1,64}$")
SAFE_SCRIPT_PATH_RE = re.compile(r"^/[a-zA-Z0-9_./\-]{1,200}$")


def _validate_recovery_fields(action: str, target: str) -> None:
    if action == "script":
        if not target or ".." in target or not SAFE_SCRIPT_PATH_RE.match(target):
            raise ValueError("recovery_target must be a valid absolute script path when recovery_action is 'script'")
    elif action == "systemctl_restart" and target:
        if not SAFE_PROC_NAME_RE.match(target):
            raise ValueError(f"Invalid systemd unit name: {target}")


class WatchedProcessCreateRequest(BaseModel):
    process_name: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_.\-]{1,64}$")
    check_type: Literal["process", "systemd"] = "process"
    enabled: bool = True
    save_log: bool = True
    recovery_action: Literal["none", "alert_only", "systemctl_restart", "script"] = "alert_only"
    recovery_target: str = Field(default="", max_length=200)
    check_interval_sec: int = Field(default=30, ge=5, le=86400)

    @model_validator(mode="after")
    def check_recovery(self) -> "WatchedProcessCreateRequest":
        _validate_recovery_fields(self.recovery_action, self.recovery_target)
        return self


class WatchedProcessUpdateRequest(BaseModel):
    process_name: str | None = Field(default=None, min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_.\-]{1,64}$")
    check_type: Literal["process", "systemd"] | None = None
    enabled: bool | None = None
    save_log: bool | None = None
    recovery_action: Literal["none", "alert_only", "systemctl_restart", "script"] | None = None
    recovery_target: str | None = Field(default=None, max_length=200)
    check_interval_sec: int | None = Field(default=None, ge=5, le=86400)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


async def _probe_server(client: httpx.AsyncClient, srv: dict[str, Any]) -> dict[str, Any]:
    public_srv = {
        "id": srv["id"],
        "name": srv["name"],
        "url": srv["url"],
        "group": srv.get("group", "default"),
        "protected_ports": store.get_protected_ports(srv),
    }
    try:
        resp = await client.get(
            f"{srv['url']}/api/v1/status",
            headers={"X-Agent-Token": srv["token"]},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            public_srv["online"] = True
            public_srv["mode"] = data.get("mode", "unknown")
            public_srv["hostname"] = data.get("hostname", srv["name"])
            public_srv["selinux_mode"] = data.get("selinux", {}).get("mode", "Unknown")
            public_srv["firewall_running"] = data.get("firewall", {}).get("running", False)
            res = data.get("resources") or {}
            if res:
                public_srv["cpu_percent"] = res.get("cpu_percent")
                public_srv["mem_percent"] = res.get("mem_percent")
        else:
            public_srv["online"] = False
            public_srv["error"] = f"HTTP {resp.status_code}"
    except httpx.RequestError as exc:
        public_srv["online"] = False
        public_srv["error"] = str(exc)
    return public_srv


@app.get("/api/servers")
async def list_servers() -> list[dict[str, Any]]:
    servers = await store.list_servers()
    async with httpx.AsyncClient() as client:
        return list(await asyncio.gather(*[_probe_server(client, s) for s in servers]))


@app.post("/api/servers")
async def add_server(req: ServerCreateRequest) -> dict[str, Any]:
    srv = await store.add_server(
        name=req.name,
        url=req.url,
        token=req.token,
        group=req.group,
        protected_ports=req.protected_ports,
    )
    await store.append_audit(
        srv["id"],
        srv["name"],
        "server/create",
        {"name": srv["name"], "url": srv["url"], "group": srv["group"], "protected_ports": srv["protected_ports"]},
        True,
        f"Registered server '{srv['name']}' ({srv['url']})",
    )
    return {
        "id": srv["id"],
        "name": srv["name"],
        "url": srv["url"],
        "group": srv["group"],
        "protected_ports": srv["protected_ports"],
    }


@app.patch("/api/servers/{server_id}")
@app.put("/api/servers/{server_id}")
async def edit_server(server_id: str, req: ServerUpdateRequest) -> dict[str, Any]:
    if req.protected_ports is not None:
        for p in req.protected_ports:
            if not (1 <= p <= 65535):
                raise HTTPException(status_code=422, detail=f"Invalid port number: {p}")
    updated = await store.update_server(
        server_id=server_id,
        name=req.name,
        url=req.url,
        token=req.token,
        group=req.group,
        protected_ports=req.protected_ports,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Server not found")
    token_changed = bool(req.token and req.token.strip())
    await store.append_audit(
        updated["id"],
        updated["name"],
        "server/update",
        {
            "name": updated["name"],
            "url": updated["url"],
            "group": updated["group"],
            "protected_ports": updated["protected_ports"],
            "token_changed": token_changed,
        },
        True,
        f"Updated server '{updated['name']}' ({updated['url']})" + (" [token updated]" if token_changed else ""),
    )
    return {
        "id": updated["id"],
        "name": updated["name"],
        "url": updated["url"],
        "group": updated["group"],
        "protected_ports": updated["protected_ports"],
    }


@app.put("/api/servers/{server_id}/protected-ports")
async def update_protected_ports(server_id: str, req: ProtectedPortsUpdateRequest) -> dict[str, Any]:
    for p in req.ports:
        if not (1 <= p <= 65535):
            raise HTTPException(status_code=422, detail=f"Invalid port number: {p}")
    updated = await store.update_protected_ports(server_id, req.ports)
    if not updated:
        raise HTTPException(status_code=404, detail="Server not found")
    await store.append_audit(
        updated["id"],
        updated["name"],
        "protected-ports/update",
        {"ports": updated["protected_ports"]},
        True,
        f"Updated protected ports: {updated['protected_ports']}",
    )
    return {"ok": True, "protected_ports": updated["protected_ports"]}


@app.delete("/api/servers/{server_id}")
async def delete_server(server_id: str) -> dict[str, Any]:
    if not await store.remove_server(server_id):
        raise HTTPException(status_code=404, detail="Server not found")
    return {"ok": True}


@app.get("/api/servers/{server_id}/status")
async def get_server_status(server_id: str) -> dict[str, Any]:
    srv = await store.get_server(server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"{srv['url']}/api/v1/status",
                headers={"X-Agent-Token": srv["token"]},
                timeout=15.0,
            )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Agent unreachable: {exc}") from exc
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    data = resp.json()
    data["protected_ports"] = store.get_protected_ports(srv)
    return data


@app.post("/api/servers/{server_id}/action/{action_path:path}")
async def proxy_action(
    server_id: str,
    action_path: str,
    payload: dict[str, Any] = Body(...),
) -> dict[str, Any]:
    if action_path not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported action: {action_path}")
    srv = await store.get_server(server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")

    if action_path == "firewall/service" and payload.get("action") == "remove" and payload.get("service") == "ssh":
        protected = store.get_protected_ports(srv)
        if 22 in protected:
            msg = f"Service 'ssh' is protected because port 22 is in protected_ports ({protected})."
            logger.warning("[BLOCKED_PLAIN] server=%s(%s) action=%s payload=%s reason=%s", srv["name"], srv["id"], action_path, json.dumps(payload, ensure_ascii=False), msg)
            await store.append_audit(srv["id"], srv["name"], action_path, payload, False, msg)
            raise HTTPException(status_code=400, detail=msg)

    if action_path == "firewall/port" and payload.get("action") == "remove":
        port_val = payload.get("port")
        protected = store.get_protected_ports(srv)
        if port_val is not None and int(port_val) in protected:
            msg = f"Port {port_val} is protected for server '{srv['name']}' ({protected}). Remove from Protected Ports first."
            logger.warning("[BLOCKED_PLAIN] server=%s(%s) action=%s payload=%s reason=%s", srv["name"], srv["id"], action_path, json.dumps(payload, ensure_ascii=False), msg)
            await store.append_audit(srv["id"], srv["name"], action_path, payload, False, msg)
            raise HTTPException(status_code=400, detail=msg)

    async with _make_http_client() as client:
        try:
            status_code, resp_data = await send_encrypted_command(
                client,
                srv,
                f"/api/v1/{action_path}",
                payload,
                timeout=15.0,
                log_plain=True,
            )
        except httpx.RequestError as exc:
            await store.append_audit(srv["id"], srv["name"], action_path, payload, False, str(exc))
            raise HTTPException(status_code=502, detail=f"Agent unreachable: {exc}") from exc
        except ValueError as exc:
            logger.error("[DECRYPT_ERR] server=%s(%s) action=%s error=%s", srv["name"], srv["id"], action_path, exc)
            await store.append_audit(srv["id"], srv["name"], action_path, payload, False, str(exc))
            raise HTTPException(status_code=502, detail=f"Invalid encrypted agent response: {exc}") from exc

    if status_code != 200:
        detail = resp_data.get("detail", str(resp_data))
        await store.append_audit(srv["id"], srv["name"], action_path, payload, False, str(detail))
        raise HTTPException(status_code=status_code, detail=detail)

    await store.append_audit(srv["id"], srv["name"], action_path, payload, True, str(resp_data.get("detail", "ok")))
    return resp_data


@app.get("/api/audit")
async def get_audit(
    limit: int = 50,
    server_id: str | None = None,
    action: str | None = None,
    success: bool | None = None,
) -> list[dict[str, Any]]:
    return await store.list_audit(limit=limit, server_id=server_id, action=action, success=success)


@app.get("/api/processes")
async def list_all_processes(server_id: str | None = None) -> list[dict[str, Any]]:
    return await store.list_processes(server_id=server_id)


@app.get("/api/servers/{server_id}/processes")
async def list_server_processes(server_id: str) -> list[dict[str, Any]]:
    if not await store.get_server(server_id):
        raise HTTPException(status_code=404, detail="Server not found")
    return await store.list_processes(server_id=server_id)


@app.post("/api/servers/{server_id}/processes")
async def add_server_process(server_id: str, req: WatchedProcessCreateRequest) -> dict[str, Any]:
    srv = await store.get_server(server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")
    proc = await store.add_process(
        server_id=server_id,
        process_name=req.process_name,
        check_type=req.check_type,
        enabled=req.enabled,
        save_log=req.save_log,
        recovery_action=req.recovery_action,
        recovery_target=req.recovery_target,
        check_interval_sec=req.check_interval_sec,
    )
    await store.append_audit(
        srv["id"],
        srv["name"],
        "process/create",
        proc,
        True,
        f"Added watched process '{req.process_name}' (action={req.recovery_action}, save_log={req.save_log})",
    )
    return proc


@app.patch("/api/processes/{process_id}")
async def update_watched_process(process_id: str, req: WatchedProcessUpdateRequest) -> dict[str, Any]:
    existing = await store.get_process(process_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Watched process not found")
    new_action = req.recovery_action if req.recovery_action is not None else existing["recovery_action"]
    new_target = req.recovery_target if req.recovery_target is not None else existing["recovery_target"]
    try:
        _validate_recovery_fields(new_action, new_target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    updated = await store.update_process(
        process_id,
        process_name=req.process_name,
        check_type=req.check_type,
        enabled=req.enabled,
        save_log=req.save_log,
        recovery_action=req.recovery_action,
        recovery_target=req.recovery_target,
        check_interval_sec=req.check_interval_sec,
    )
    assert updated is not None
    return updated


@app.delete("/api/processes/{process_id}")
async def delete_watched_process(process_id: str) -> dict[str, Any]:
    if not await store.remove_process(process_id):
        raise HTTPException(status_code=404, detail="Watched process not found")
    return {"ok": True}


@app.post("/api/processes/poll")
async def poll_processes(server_id: str | None = None) -> dict[str, Any]:
    results = await monitor.run_once(force=True, server_id=server_id)
    return {"checked": len(results), "results": results}


@app.get("/api/process-logs")
async def get_process_logs(
    limit: int = 100,
    server_id: str | None = None,
    process_id: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    return await store.list_process_logs(limit=limit, server_id=server_id, process_id=process_id, status=status)


class AgentLogDecryptRequest(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=500)


@app.get("/api/controller-logs")
async def get_controller_plain_logs(limit: int = 100) -> dict[str, Any]:
    return {"logs": list_controller_plain_logs(limit=limit)}


@app.get("/api/servers/{server_id}/agent-logs")
async def fetch_agent_logs(
    server_id: str,
    limit: int = 100,
    decrypt: bool = True,
) -> dict[str, Any]:
    srv = await store.get_server(server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")
    safe_limit = max(1, min(limit, 500))
    async with _make_http_client() as client:
        try:
            resp = await client.get(
                f"{srv['url']}/api/v1/logs",
                params={"limit": safe_limit},
                headers={"X-Agent-Token": srv["token"]},
                timeout=15.0,
            )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Agent unreachable: {exc}") from exc
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)

    raw_logs = resp.json().get("logs", [])
    processed = [decrypt_agent_log_entry(entry, srv["token"], decrypt=decrypt) for entry in raw_logs]
    return {
        "server_id": srv["id"],
        "server_name": srv["name"],
        "decrypted": decrypt,
        "logs": processed,
    }


@app.post("/api/servers/{server_id}/agent-logs/decrypt")
async def decrypt_agent_logs_manual(server_id: str, req: AgentLogDecryptRequest) -> dict[str, Any]:
    srv = await store.get_server(server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")
    results = [decrypt_raw_log_line(line, srv["token"]) for line in req.lines]
    return {
        "server_id": srv["id"],
        "server_name": srv["name"],
        "results": results,
    }
