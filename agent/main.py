import os
import platform
from typing import Any, Optional, Union

from fastapi import Depends, FastAPI, Header, HTTPException, status

from agent.linux_backend import LinuxBackend
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
    SELinuxBooleanRequest,
    SELinuxModeRequest,
    SELinuxPortRequest,
)

AGENT_TOKEN = os.getenv("AGENT_TOKEN", "dev-agent-token")
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

app = FastAPI(
    title="Linux Access Control Agent",
    description="Lightweight FastAPI agent for firewalld, SELinux, nmcli, and socket inspection",
    version="1.0.0",
)


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
