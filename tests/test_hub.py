from fastapi.testclient import TestClient

from agent.main import app as agent_app
from controller.main import app as controller_app

agent_client = TestClient(agent_app)
ctrl_client = TestClient(controller_app)

HEADERS = {"X-Agent-Token": "dev-agent-token"}


def test_agent_auth_required():
    res = agent_client.get("/api/v1/status")
    assert res.status_code == 401

    res_bad = agent_client.get("/api/v1/status", headers={"X-Agent-Token": "wrong"})
    assert res_bad.status_code == 401


def test_agent_status_and_ssh_lockout_guard():
    res = agent_client.get("/api/v1/status", headers=HEADERS)
    assert res.status_code == 200
    data = res.json()
    assert "listening_ports" in data
    assert "firewall" in data
    assert "selinux" in data
    assert "network" in data

    # Attempting to remove protected SSH port 22 must be blocked
    res_ssh = agent_client.post(
        "/api/v1/firewall/port",
        headers=HEADERS,
        json={"zone": "public", "port": 22, "protocol": "tcp", "action": "remove"},
    )
    assert res_ssh.status_code == 400
    assert "protected" in res_ssh.json()["detail"].lower()


def test_agent_firewall_selinux_network_mutations():
    # Add & remove firewall port 9090
    r_add = agent_client.post(
        "/api/v1/firewall/port",
        headers=HEADERS,
        json={"zone": "public", "port": 9090, "protocol": "tcp", "action": "add"},
    )
    assert r_add.status_code == 200

    r_rem = agent_client.post(
        "/api/v1/firewall/port",
        headers=HEADERS,
        json={"zone": "public", "port": 9090, "protocol": "tcp", "action": "remove"},
    )
    assert r_rem.status_code == 200

    # firewall-config features: service, masquerade, forward-port, source, icmp, control
    assert agent_client.post(
        "/api/v1/firewall/service",
        headers=HEADERS,
        json={"zone": "public", "service": "https", "action": "add"},
    ).status_code == 200
    assert agent_client.post(
        "/api/v1/firewall/masquerade",
        headers=HEADERS,
        json={"zone": "public", "enabled": True},
    ).status_code == 200
    assert agent_client.post(
        "/api/v1/firewall/forward-port",
        headers=HEADERS,
        json={"zone": "public", "port": 80, "protocol": "tcp", "to_port": 8080, "action": "add"},
    ).status_code == 200
    assert agent_client.post(
        "/api/v1/firewall/source",
        headers=HEADERS,
        json={"zone": "public", "source": "10.0.0.0/8", "action": "add"},
    ).status_code == 200
    assert agent_client.post(
        "/api/v1/firewall/icmp",
        headers=HEADERS,
        json={"zone": "public", "icmp_type": "echo-request", "action": "add"},
    ).status_code == 200
    assert agent_client.post(
        "/api/v1/firewall/control",
        headers=HEADERS,
        json={"command": "reload"},
    ).status_code == 200

    # SELinux mode & boolean
    r_se = agent_client.post(
        "/api/v1/selinux/mode",
        headers=HEADERS,
        json={"mode": "Permissive"},
    )
    assert r_se.status_code == 200

    r_bool = agent_client.post(
        "/api/v1/selinux/boolean",
        headers=HEADERS,
        json={"name": "httpd_can_network_connect", "value": True},
    )
    assert r_bool.status_code == 200

    # Network IPv4 update
    r_net = agent_client.post(
        "/api/v1/network/ipv4",
        headers=HEADERS,
        json={
            "connection": "ens160",
            "method": "manual",
            "address": "192.168.10.55/24",
            "gateway": "192.168.10.1",
            "dns": "1.1.1.1",
        },
    )
    assert r_net.status_code == 200


def test_agent_rejects_command_injection():
    r_bad_ip = agent_client.post(
        "/api/v1/firewall/rich-rule",
        headers=HEADERS,
        json={
            "zone": "public",
            "source_ip": "192.168.1.1; rm -rf /",
            "port": 8080,
            "protocol": "tcp",
            "rule_action": "accept",
            "action": "add",
        },
    )
    assert r_bad_ip.status_code == 422


def test_controller_dashboard_and_registry():
    r_ui = ctrl_client.get("/")
    assert r_ui.status_code == 200
    assert "Access Control Hub" in r_ui.text

    r_create = ctrl_client.post(
        "/api/servers",
        json={
            "name": "test-node",
            "url": "http://127.0.0.1:9199",
            "token": "dev-agent-token",
            "group": "staging",
        },
    )
    assert r_create.status_code == 200
    created = r_create.json()
    srv_id = created["id"]
    assert created["protected_ports"] == [22, 9199]

    r_upd = ctrl_client.put(
        f"/api/servers/{srv_id}/protected-ports",
        json={"ports": [22, 8100, 1521]},
    )
    assert r_upd.status_code == 200
    assert r_upd.json()["protected_ports"] == [22, 1521, 8100]

    # Controller must block removing a server's protected port before forwarding to Agent
    r_block = ctrl_client.post(
        f"/api/servers/{srv_id}/action/firewall/port",
        json={"zone": "public", "port": 1521, "protocol": "tcp", "action": "remove"},
    )
    assert r_block.status_code == 400
    assert "protected" in r_block.json()["detail"].lower()

    r_del = ctrl_client.delete(f"/api/servers/{srv_id}")
    assert r_del.status_code == 200
