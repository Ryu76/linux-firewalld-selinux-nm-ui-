import asyncio
import os
import tempfile
from pathlib import Path

_TEST_LOG_DIR = Path(tempfile.mkdtemp(prefix="lach_test_logs_"))
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("PROCESS_MONITOR_ENABLED", "0")
os.environ.setdefault("AGENT_LOG_FILE", str(_TEST_LOG_DIR / "agent.log"))
os.environ.setdefault("AGENT_ENCRYPTED_LOG_FILE", str(_TEST_LOG_DIR / "agent_encrypted.jsonl"))
os.environ.setdefault("CONTROLLER_LOG_FILE", str(_TEST_LOG_DIR / "controller.log"))

import httpx
from fastapi.testclient import TestClient

import controller.main as controller_module
from agent.crypto import encrypt_payload
from agent.main import app as agent_app
from controller.main import app as controller_app, monitor

agent_client = TestClient(agent_app)

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
    assert "resources" in data
    assert "mem_percent" in data["resources"]
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
    with TestClient(controller_app) as ctrl_client:
        r_ui = ctrl_client.get("/")
        assert r_ui.status_code == 200
        assert "Access Control Hub" in r_ui.text
        assert 'data-tab="processes"' in r_ui.text
        assert 'data-logtab="agent-enc"' in r_ui.text
        assert "/static/style.css?v=9" in r_ui.text
        assert "/static/app.js?v=8" in r_ui.text

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

        # Edit existing server IP/URL & name while preserving ID and existing token
        r_edit = ctrl_client.patch(
            f"/api/servers/{srv_id}",
            json={
                "name": "test-node-renamed",
                "url": "http://127.0.0.1:8754",
                "token": "",
                "group": "production",
            },
        )
        assert r_edit.status_code == 200
        edited = r_edit.json()
        assert edited["id"] == srv_id
        assert edited["name"] == "test-node-renamed"
        assert edited["url"] == "http://127.0.0.1:8754"
        assert edited["protected_ports"] == [22, 8754]

        r_upd = ctrl_client.put(
            f"/api/servers/{srv_id}/protected-ports",
            json={"ports": [22, 8754, 1521]},
        )
        assert r_upd.status_code == 200
        assert r_upd.json()["protected_ports"] == [22, 1521, 8754]

        # Controller must block removing a server's protected port before forwarding to Agent
        r_block = ctrl_client.post(
            f"/api/servers/{srv_id}/action/firewall/port",
            json={"zone": "public", "port": 1521, "protocol": "tcp", "action": "remove"},
        )
        assert r_block.status_code == 400
        assert "protected" in r_block.json()["detail"].lower()

        # Verify audit log persistence & query filters
        r_audit = ctrl_client.get(f"/api/audit?server_id={srv_id}&success=false")
        assert r_audit.status_code == 200
        audits = r_audit.json()
        assert len(audits) == 1
        assert audits[0]["action"] == "firewall/port"
        assert audits[0]["server_name"] == "test-node-renamed"
        assert audits[0]["success"] is False

        r_del = ctrl_client.delete(f"/api/servers/{srv_id}")
        assert r_del.status_code == 200


def test_agent_process_check_and_recover():
    r_chk = agent_client.post(
        "/api/v1/processes/check",
        headers=HEADERS,
        json={
            "targets": [
                {"name": "nginx", "check_type": "process"},
                {"name": "nonexistent-svc", "check_type": "systemd"},
            ]
        },
    )
    assert r_chk.status_code == 200
    res_map = {item["name"]: item["status"] for item in r_chk.json()["results"]}
    assert res_map["nginx"] == "running"
    assert res_map["nonexistent-svc"] == "stopped"

    r_rec = agent_client.post(
        "/api/v1/processes/recover",
        headers=HEADERS,
        json={"action_type": "systemctl_restart", "target": "nonexistent-svc"},
    )
    assert r_rec.status_code == 200

    # Command injection / path traversal in recovery script must be rejected
    r_bad = agent_client.post(
        "/api/v1/processes/recover",
        headers=HEADERS,
        json={"action_type": "script", "target": "/opt/scripts/../../bin/sh"},
    )
    assert r_bad.status_code == 422


def test_controller_process_monitor_and_log_toggle():
    with TestClient(controller_app) as ctrl_client:
        srv = ctrl_client.post(
            "/api/servers",
            json={
                "name": "proc-test-node",
                "url": "http://agent-test",
                "token": "dev-agent-token",
                "group": "production",
            },
        ).json()
        srv_id = srv["id"]

        # 1) Running process with save_log=True
        p_running = ctrl_client.post(
            f"/api/servers/{srv_id}/processes",
            json={
                "process_name": "nginx",
                "check_type": "process",
                "save_log": True,
                "recovery_action": "alert_only",
                "check_interval_sec": 10,
            },
        )
        assert p_running.status_code == 200
        p_run_id = p_running.json()["id"]

        # 2) Stopped process with save_log=False and auto systemctl_restart
        p_stopped = ctrl_client.post(
            f"/api/servers/{srv_id}/processes",
            json={
                "process_name": "custom-worker",
                "check_type": "systemd",
                "save_log": False,
                "recovery_action": "systemctl_restart",
                "recovery_target": "custom-worker",
                "check_interval_sec": 10,
            },
        )
        assert p_stopped.status_code == 200
        p_stop_id = p_stopped.json()["id"]

        # Run monitor poll against in-process agent_app
        async def _poll():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=agent_app)) as client:
                return await monitor.run_once(force=True, server_id=srv_id, http_client=client)

        outcomes = asyncio.run(_poll())
        assert len(outcomes) == 2

        # Verify process states updated
        procs = {p["id"]: p for p in ctrl_client.get(f"/api/servers/{srv_id}/processes").json()}
        assert procs[p_run_id]["last_status"] == "running"
        assert procs[p_stop_id]["last_status"] == "recovered"

        # Verify save_log=True recorded log, save_log=False did NOT record log
        logs_run = ctrl_client.get(f"/api/process-logs?process_id={p_run_id}").json()
        logs_stop = ctrl_client.get(f"/api/process-logs?process_id={p_stop_id}").json()
        assert len(logs_run) == 1
        assert logs_run[0]["status"] == "running"
        assert len(logs_stop) == 0

        # Update per-process settings: enable save_log & switch recovery action to script
        r_patch = ctrl_client.patch(
            f"/api/processes/{p_stop_id}",
            json={
                "save_log": True,
                "recovery_action": "script",
                "recovery_target": "/opt/scripts/recover_worker.sh",
            },
        )
        assert r_patch.status_code == 200
        assert r_patch.json()["save_log"] is True
        assert r_patch.json()["recovery_action"] == "script"

        # Invalid script path must be rejected
        r_bad_patch = ctrl_client.patch(
            f"/api/processes/{p_stop_id}",
            json={"recovery_target": "relative/path.sh"},
        )
        assert r_bad_patch.status_code == 422

        assert ctrl_client.delete(f"/api/processes/{p_run_id}").status_code == 200
        assert ctrl_client.delete(f"/api/processes/{p_stop_id}").status_code == 200
        assert ctrl_client.delete(f"/api/servers/{srv_id}").status_code == 200


def test_encrypted_command_channel_and_log_decryption():
    # 1) Tampered / wrong-key encrypted packet must be rejected by Agent
    r_tampered = agent_client.post(
        "/api/v1/firewall/port",
        headers={**HEADERS, "X-Payload-Encrypted": "1"},
        json={"enc": "tampered-invalid-ciphertext"},
    )
    assert r_tampered.status_code == 400

    wrong_key_enc = encrypt_payload(
        {"zone": "public", "port": 9443, "protocol": "tcp", "action": "add"},
        "wrong-secret-token",
    )
    r_wrong_key = agent_client.post(
        "/api/v1/firewall/port",
        headers={**HEADERS, "X-Payload-Encrypted": "1"},
        json={"enc": wrong_key_enc},
    )
    assert r_wrong_key.status_code == 400

    # 2) End-to-end Controller -> encrypted command -> Agent -> encrypted log -> Controller decrypt
    controller_module.http_transport = httpx.ASGITransport(app=agent_app)
    try:
        with TestClient(controller_app) as ctrl_client:
            srv = ctrl_client.post(
                "/api/servers",
                json={
                    "name": "enc-test-node",
                    "url": "http://agent-enc-test",
                    "token": "dev-agent-token",
                    "group": "production",
                },
            ).json()
            srv_id = srv["id"]

            r_act = ctrl_client.post(
                f"/api/servers/{srv_id}/action/firewall/port",
                json={"zone": "public", "port": 9443, "protocol": "tcp", "action": "add"},
            )
            assert r_act.status_code == 200
            assert r_act.json()["ok"] is True

            # Verify Agent log files contain ONLY ciphertext (no plaintext port 9443)
            agent_log_text = (_TEST_LOG_DIR / "agent.log").read_text(encoding="utf-8")
            agent_jsonl_text = (_TEST_LOG_DIR / "agent_encrypted.jsonl").read_text(encoding="utf-8")
            assert "[ENC_LOG]" in agent_log_text
            assert "9443" not in agent_log_text
            assert "9443" not in agent_jsonl_text

            # Verify Controller log file contains unencrypted plaintext command
            ctrl_logs_resp = ctrl_client.get("/api/controller-logs?limit=20")
            assert ctrl_logs_resp.status_code == 200
            ctrl_lines = "\n".join(ctrl_logs_resp.json()["logs"])
            assert "[OUTBOUND_PLAIN]" in ctrl_lines
            assert "9443" in ctrl_lines

            # Fetch raw (undecrypted) Agent logs from Controller
            r_raw = ctrl_client.get(f"/api/servers/{srv_id}/agent-logs?limit=10&decrypt=false")
            assert r_raw.status_code == 200
            raw_entries = r_raw.json()["logs"]
            assert len(raw_entries) >= 1
            assert "decrypted" not in raw_entries[0]
            assert "9443" not in raw_entries[0]["enc"]

            # Fetch and immediately decrypt Agent logs on Controller
            r_dec = ctrl_client.get(f"/api/servers/{srv_id}/agent-logs?limit=10&decrypt=true")
            assert r_dec.status_code == 200
            dec_entries = r_dec.json()["logs"]
            latest = dec_entries[0]["decrypted"]
            assert latest["path"] == "/api/v1/firewall/port"
            assert latest["wire_encrypted"] is True
            assert latest["payload"]["port"] == 9443

            # Manual decryption endpoint works for raw [ENC_LOG] lines and JSONL lines
            sample_line = [ln for ln in agent_log_text.splitlines() if "[ENC_LOG]" in ln][-1]
            r_manual = ctrl_client.post(
                f"/api/servers/{srv_id}/agent-logs/decrypt",
                json={"lines": [sample_line, raw_entries[0]["enc"]]},
            )
            assert r_manual.status_code == 200
            manual_res = r_manual.json()["results"]
            assert manual_res[0]["error"] is None
            assert manual_res[0]["decrypted"]["payload"]["port"] == 9443
            assert manual_res[1]["decrypted"]["payload"]["port"] == 9443

            assert ctrl_client.delete(f"/api/servers/{srv_id}").status_code == 200
    finally:
        controller_module.http_transport = None
