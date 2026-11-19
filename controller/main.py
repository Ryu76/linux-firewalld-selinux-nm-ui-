import asyncio
from pathlib import Path
from typing import Any

import httpx
from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from controller.store import HubStore

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
app = FastAPI(
    title="Linux Access Control Hub (Controller)",
    description="Multi-server web dashboard controller for Linux firewalld, SELinux, and nmcli agents",
    version="1.0.0",
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class ServerCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    url: str = Field(min_length=7, max_length=255)
    token: str = Field(min_length=1, max_length=255)
    group: str = Field(default="default", max_length=40)
    protected_ports: list[int] | None = None


class ProtectedPortsUpdateRequest(BaseModel):
    ports: list[int] = Field(default_factory=list)


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
        else:
            public_srv["online"] = False
            public_srv["error"] = f"HTTP {resp.status_code}"
    except httpx.RequestError as exc:
        public_srv["online"] = False
        public_srv["error"] = str(exc)
    return public_srv


@app.get("/api/servers")
async def list_servers() -> list[dict[str, Any]]:
    servers = store.list_servers()
    async with httpx.AsyncClient() as client:
        return list(await asyncio.gather(*[_probe_server(client, s) for s in servers]))


@app.post("/api/servers")
def add_server(req: ServerCreateRequest) -> dict[str, Any]:
    srv = store.add_server(
        name=req.name,
        url=req.url,
        token=req.token,
        group=req.group,
        protected_ports=req.protected_ports,
    )
    return {
        "id": srv["id"],
        "name": srv["name"],
        "url": srv["url"],
        "group": srv["group"],
        "protected_ports": srv["protected_ports"],
    }


@app.put("/api/servers/{server_id}/protected-ports")
def update_protected_ports(server_id: str, req: ProtectedPortsUpdateRequest) -> dict[str, Any]:
    for p in req.ports:
        if not (1 <= p <= 65535):
            raise HTTPException(status_code=422, detail=f"Invalid port number: {p}")
    updated = store.update_protected_ports(server_id, req.ports)
    if not updated:
        raise HTTPException(status_code=404, detail="Server not found")
    store.append_audit(
        updated["id"],
        updated["name"],
        "protected-ports/update",
        {"ports": updated["protected_ports"]},
        True,
        f"Updated protected ports: {updated['protected_ports']}",
    )
    return {"ok": True, "protected_ports": updated["protected_ports"]}


@app.delete("/api/servers/{server_id}")
def delete_server(server_id: str) -> dict[str, Any]:
    if not store.remove_server(server_id):
        raise HTTPException(status_code=404, detail="Server not found")
    return {"ok": True}


@app.get("/api/servers/{server_id}/status")
async def get_server_status(server_id: str) -> dict[str, Any]:
    srv = store.get_server(server_id)
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
    srv = store.get_server(server_id)
    if not srv:
        raise HTTPException(status_code=404, detail="Server not found")

    if action_path == "firewall/service" and payload.get("action") == "remove" and payload.get("service") == "ssh":
        protected = store.get_protected_ports(srv)
        if 22 in protected:
            msg = f"Service 'ssh' is protected because port 22 is in protected_ports ({protected})."
            store.append_audit(srv["id"], srv["name"], action_path, payload, False, msg)
            raise HTTPException(status_code=400, detail=msg)

    if action_path == "firewall/port" and payload.get("action") == "remove":
        port_val = payload.get("port")
        protected = store.get_protected_ports(srv)
        if port_val is not None and int(port_val) in protected:
            msg = f"Port {port_val} is protected for server '{srv['name']}' ({protected}). Remove from Protected Ports first."
            store.append_audit(srv["id"], srv["name"], action_path, payload, False, msg)
            raise HTTPException(status_code=400, detail=msg)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{srv['url']}/api/v1/{action_path}",
                headers={"X-Agent-Token": srv["token"]},
                json=payload,
                timeout=15.0,
            )
        except httpx.RequestError as exc:
            store.append_audit(srv["id"], srv["name"], action_path, payload, False, str(exc))
            raise HTTPException(status_code=502, detail=f"Agent unreachable: {exc}") from exc

    if resp.status_code != 200:
        detail = resp.json().get("detail", resp.text) if "application/json" in resp.headers.get("content-type", "") else resp.text
        store.append_audit(srv["id"], srv["name"], action_path, payload, False, str(detail))
        raise HTTPException(status_code=resp.status_code, detail=detail)

    result = resp.json()
    store.append_audit(srv["id"], srv["name"], action_path, payload, True, result.get("detail", "ok"))
    return result


@app.get("/api/audit")
def get_audit(limit: int = 50) -> list[dict[str, Any]]:
    return store.list_audit(limit=limit)
