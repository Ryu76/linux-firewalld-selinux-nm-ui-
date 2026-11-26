import json
import os
import platform
import time
from typing import Any, Optional, Union

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import JSONResponse

from agent.crypto import decrypt_payload, encrypt_payload
from agent.linux_backend import LinuxBackend
from agent.logger import list_encrypted_agent_logs, mutating_context, record_encrypted_agent_log
from agent.mock_backend import MockLinuxBackend
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
    ProcessCheckRequest,
    ProcessRecoverRequest,
    SELinuxBooleanRequest,
    SELinuxModeRequest,
    SELinuxPortRequest,
)

AGENT_TOKEN = os.getenv("AGENT_TOKEN", "dev-agent-token")
AGENT_REQUIRE_ENCRYPTED = os.getenv("AGENT_REQUIRE_ENCRYPTED", "0")
USE_MOCK = os.getenv("AGENT_MOCK", "auto")
PROTECTED_PORTS = {
    int(p.strip())
    for p in os.getenv("PROTECTED_PORTS", "22").split(",")
    if p.strip().isdigit()
}


def create_backend() -> Union[LinuxBackend, MockLinuxBackend]:
    if USE_MOCK == "1" or (USE_MOCK == "auto" and platform.system() != "Linux"):
        hostname = os.getenv("AGENT_HOSTNAME", "rocky9-web-01")
        return MockLinuxBackend(hostname=hostname)
    return LinuxBackend()


backend = create_backend()


class EncryptedCommandMiddleware:
    """ASGI middleware that decrypts incoming command envelopes, encrypts responses, and stores encrypted-only logs."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET")
        path: str = scope.get("path", "")
        if method not in ("POST", "PUT", "PATCH", "DELETE") or not path.startswith("/api/v1/"):
            await self.app(scope, receive, send)
            return

        headers_dict = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        req_token = headers_dict.get("x-agent-token")
        encrypted_hdr = headers_dict.get("x-payload-encrypted") == "1"

        chunks: list[bytes] = []
        while True:
            msg = await receive()
            if msg["type"] == "http.request":
                chunks.append(msg.get("body", b""))
                if not msg.get("more_body", False):
                    break
            elif msg["type"] == "http.disconnect":
                return
        raw_body = b"".join(chunks)

        parsed_raw: Any = None
        if raw_body:
            try:
                parsed_raw = json.loads(raw_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed_raw = None

        is_wire_encrypted = encrypted_hdr or (
            isinstance(parsed_raw, dict) and set(parsed_raw.keys()) == {"enc"} and isinstance(parsed_raw.get("enc"), str)
        )

        if is_wire_encrypted:
            if req_token != AGENT_TOKEN:
                resp = JSONResponse(status_code=401, content={"detail": "Invalid or missing X-Agent-Token"})
                await resp(scope, receive, send)
                return
            enc_str = parsed_raw.get("enc") if isinstance(parsed_raw, dict) else None
            if not isinstance(enc_str, str):
                resp = JSONResponse(status_code=400, content={"detail": "Missing 'enc' field in encrypted request"})
                await resp(scope, receive, send)
                return
            try:
                decrypted_obj = decrypt_payload(enc_str, AGENT_TOKEN, max_age_sec=300.0)
            except ValueError as exc:
                resp = JSONResponse(status_code=400, content={"detail": str(exc)})
                await resp(scope, receive, send)
                return
            effective_body = json.dumps(decrypted_obj, ensure_ascii=False).encode("utf-8")
            plain_payload: Any = decrypted_obj
        else:
            if AGENT_REQUIRE_ENCRYPTED == "1":
                resp = JSONResponse(status_code=400, content={"detail": "Encrypted command payload is required"})
                await resp(scope, receive, send)
                return
            effective_body = raw_body
            plain_payload = parsed_raw if parsed_raw is not None else raw_body.decode("utf-8", errors="replace")

        new_headers = [
            (k, v)
            for k, v in scope.get("headers", [])
            if k.lower() not in (b"content-length",)
        ]
        new_headers.append((b"content-length", str(len(effective_body)).encode("ascii")))
        new_scope = dict(scope, headers=new_headers)

        body_sent = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": effective_body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        resp_status = 500
        resp_headers: list[tuple[bytes, bytes]] = []
        resp_chunks: list[bytes] = []

        async def capture_send(message: dict[str, Any]) -> None:
            nonlocal resp_status, resp_headers
            if message["type"] == "http.response.start":
                resp_status = message["status"]
                resp_headers = list(message.get("headers", []))
            elif message["type"] == "http.response.body":
                resp_chunks.append(message.get("body", b""))

        is_mutation = path != "/api/v1/processes/check"
        ctx_token = mutating_context.set(is_mutation and req_token == AGENT_TOKEN)
        start = time.perf_counter()
        try:
            await self.app(new_scope, replay_receive, capture_send)
        finally:
            mutating_context.reset(ctx_token)
        elapsed_ms = (time.perf_counter() - start) * 1000

        full_resp_body = b"".join(resp_chunks)
        resp_json: Any = None
        if full_resp_body:
            try:
                resp_json = json.loads(full_resp_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                resp_json = None

        if is_mutation and resp_status != 401:
            client_info = scope.get("client")
            client_host = client_info[0] if client_info else "unknown"
            record_encrypted_agent_log(
                "inbound_command",
                {
                    "method": method,
                    "path": path,
                    "client": client_host,
                    "status": resp_status,
                    "elapsed_ms": round(elapsed_ms, 1),
                    "wire_encrypted": is_wire_encrypted,
                    "payload": plain_payload,
                    "response": resp_json if resp_json is not None else full_resp_body.decode("utf-8", errors="replace")[:300],
                },
                AGENT_TOKEN,
            )

        out_body = full_resp_body
        out_headers = [(k, v) for k, v in resp_headers if k.lower() != b"content-length"]
        if is_wire_encrypted and isinstance(resp_json, dict):
            enc_resp = encrypt_payload(resp_json, AGENT_TOKEN)
            out_body = json.dumps({"enc": enc_resp}, separators=(",", ":")).encode("utf-8")
            out_headers.append((b"x-payload-encrypted", b"1"))
        out_headers.append((b"content-length", str(len(out_body)).encode("ascii")))

        await send({"type": "http.response.start", "status": resp_status, "headers": out_headers})
        await send({"type": "http.response.body", "body": out_body, "more_body": False})


app = FastAPI(
    title="Linux Access Control Agent",
    description="Lightweight FastAPI agent for firewalld, SELinux, nmcli, and socket inspection",
    version="1.0.0",
)
app.add_middleware(EncryptedCommandMiddleware)


def verify_token(x_agent_token: Optional[str] = Header(default=None)) -> None:
    if x_agent_token != AGENT_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Agent-Token",
        )


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "mode": backend.mode_label}


@app.get("/api/v1/status", dependencies=[Depends(verify_token)])
def get_status() -> dict[str, Any]:
    return backend.get_status()


@app.get("/api/v1/logs", dependencies=[Depends(verify_token)])
def get_encrypted_logs(limit: int = 100) -> dict[str, Any]:
    return {"logs": list_encrypted_agent_logs(limit=limit)}


@app.post("/api/v1/firewall/port", dependencies=[Depends(verify_token)])
def firewall_port(req: FirewallPortRequest) -> dict[str, Any]:
    if req.action == "remove" and req.port in PROTECTED_PORTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Port {req.port} is protected (SSH lockout guard). Remove from PROTECTED_PORTS to override.",
        )
    try:
        return backend.manage_firewall_port(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/firewall/rich-rule", dependencies=[Depends(verify_token)])
def firewall_rich_rule(req: FirewallRichRuleRequest) -> dict[str, Any]:
    try:
        return backend.manage_firewall_rich_rule(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/firewall/service", dependencies=[Depends(verify_token)])
def firewall_service(req: FirewallServiceRequest) -> dict[str, Any]:
    try:
        return backend.manage_firewall_service(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/firewall/masquerade", dependencies=[Depends(verify_token)])
def firewall_masquerade(req: FirewallMasqueradeRequest) -> dict[str, Any]:
    try:
        return backend.manage_firewall_masquerade(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/firewall/forward-port", dependencies=[Depends(verify_token)])
def firewall_forward_port(req: FirewallForwardPortRequest) -> dict[str, Any]:
    try:
        return backend.manage_firewall_forward_port(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/firewall/source", dependencies=[Depends(verify_token)])
def firewall_source(req: FirewallSourceRequest) -> dict[str, Any]:
    try:
        return backend.manage_firewall_source(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/firewall/interface", dependencies=[Depends(verify_token)])
def firewall_interface(req: FirewallInterfaceRequest) -> dict[str, Any]:
    try:
        return backend.manage_firewall_interface(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/firewall/icmp", dependencies=[Depends(verify_token)])
def firewall_icmp(req: FirewallIcmpRequest) -> dict[str, Any]:
    try:
        return backend.manage_firewall_icmp(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/firewall/control", dependencies=[Depends(verify_token)])
def firewall_control(req: FirewallControlRequest) -> dict[str, Any]:
    try:
        return backend.control_firewall(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/selinux/mode", dependencies=[Depends(verify_token)])
def selinux_mode(req: SELinuxModeRequest) -> dict[str, Any]:
    try:
        return backend.set_selinux_mode(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/selinux/port", dependencies=[Depends(verify_token)])
def selinux_port(req: SELinuxPortRequest) -> dict[str, Any]:
    try:
        return backend.manage_selinux_port(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/selinux/boolean", dependencies=[Depends(verify_token)])
def selinux_boolean(req: SELinuxBooleanRequest) -> dict[str, Any]:
    try:
        return backend.set_selinux_boolean(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/network/ipv4", dependencies=[Depends(verify_token)])
def network_ipv4(req: NetworkIPv4Request) -> dict[str, Any]:
    try:
        return backend.configure_network_ipv4(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/processes/check", dependencies=[Depends(verify_token)])
def check_processes(req: ProcessCheckRequest) -> dict[str, Any]:
    try:
        return backend.check_processes(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@app.post("/api/v1/processes/recover", dependencies=[Depends(verify_token)])
def recover_process(req: ProcessRecoverRequest) -> dict[str, Any]:
    try:
        return backend.recover_process(req)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
