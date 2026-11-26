import asyncio
import contextlib
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import httpx

from controller.agent_client import send_encrypted_command
from controller.store import HubStore


class ProcessMonitor:
    """Periodic controller-side polling monitor for per-server watched processes."""

    def __init__(self, store: HubStore, tick_seconds: float = 5.0) -> None:
        self.store = store
        self.tick_seconds = tick_seconds
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()

    def start(self) -> None:
        if os.getenv("PROCESS_MONITOR_ENABLED", "1") == "0":
            return
        if self._task is None or self._task.done():
            self._stop_event.clear()
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._stop_event.set()
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _loop(self) -> None:
        while not self._stop_event.is_set():
            with contextlib.suppress(Exception):
                await self.run_once(force=False)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.tick_seconds)
            except TimeoutError:
                continue

    def _is_due(self, proc: dict[str, Any], now: datetime) -> bool:
        raw_ts = proc.get("last_checked_at")
        if not raw_ts:
            return True
        try:
            last_dt = datetime.fromisoformat(raw_ts)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return True
        interval = max(5, int(proc.get("check_interval_sec", 30)))
        return (now - last_dt).total_seconds() >= interval

    async def run_once(
        self,
        force: bool = False,
        server_id: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        procs = await self.store.list_processes(server_id=server_id, enabled_only=True)
        due_procs = [p for p in procs if force or self._is_due(p, now)]
        if not due_procs:
            return []

        servers = {s["id"]: s for s in await self.store.list_servers()}
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for proc in due_procs:
            if proc["server_id"] in servers:
                grouped[proc["server_id"]].append(proc)

        outcomes: list[dict[str, Any]] = []
        owns_client = http_client is None
        client = http_client or httpx.AsyncClient()
        try:
            for sid, srv_procs in grouped.items():
                srv = servers[sid]
                outcomes.extend(await self._check_server_processes(client, srv, srv_procs, now))
        finally:
            if owns_client:
                await client.aclose()
        return outcomes

    async def _check_server_processes(
        self,
        client: httpx.AsyncClient,
        srv: dict[str, Any],
        procs: list[dict[str, Any]],
        now: datetime,
    ) -> list[dict[str, Any]]:
        targets = [{"name": p["process_name"], "check_type": p["check_type"]} for p in procs]
        outcomes: list[dict[str, Any]] = []

        try:
            status_code, check_data = await send_encrypted_command(
                client,
                srv,
                "/api/v1/processes/check",
                {"targets": targets},
                timeout=15.0,
                log_plain=False,
            )
            if status_code != 200:
                raise RuntimeError(f"HTTP {status_code}: {check_data.get('detail', check_data)}")
            result_map = {
                (item["name"], item["check_type"]): item
                for item in check_data.get("results", [])
            }
        except (httpx.RequestError, RuntimeError, ValueError) as exc:
            err_msg = f"Agent unreachable: {exc}"
            for proc in procs:
                await self.store.update_process_status(proc["id"], "unreachable", err_msg, now)
                if proc["save_log"]:
                    await self.store.append_process_log(
                        srv["id"],
                        srv["name"],
                        proc["id"],
                        proc["process_name"],
                        "unreachable",
                        "none",
                        False,
                        err_msg,
                    )
                outcomes.append({"process_id": proc["id"], "status": "unreachable", "detail": err_msg})
            return outcomes

        for proc in procs:
            item = result_map.get((proc["process_name"], proc["check_type"]))
            raw_status = item["status"] if item else "stopped"
            detail = item.get("detail", "") if item else "missing check result"

            if raw_status == "running":
                await self.store.update_process_status(proc["id"], "running", detail, now)
                if proc["save_log"]:
                    await self.store.append_process_log(
                        srv["id"],
                        srv["name"],
                        proc["id"],
                        proc["process_name"],
                        "running",
                        "none",
                        True,
                        detail,
                    )
                outcomes.append({"process_id": proc["id"], "status": "running", "detail": detail})
                continue

            outcome = await self._handle_stopped_process(client, srv, proc, detail, now)
            outcomes.append(outcome)
        return outcomes

    async def _handle_stopped_process(
        self,
        client: httpx.AsyncClient,
        srv: dict[str, Any],
        proc: dict[str, Any],
        check_detail: str,
        now: datetime,
    ) -> dict[str, Any]:
        action = proc["recovery_action"]
        if action in ("none", "alert_only"):
            msg = f"Process '{proc['process_name']}' is stopped ({check_detail})"
            await self.store.update_process_status(proc["id"], "stopped", msg, now)
            if action == "alert_only":
                await self.store.append_audit(
                    srv["id"],
                    srv["name"],
                    "process/alert",
                    {"process_id": proc["id"], "process_name": proc["process_name"]},
                    False,
                    msg,
                )
            if proc["save_log"]:
                await self.store.append_process_log(
                    srv["id"],
                    srv["name"],
                    proc["id"],
                    proc["process_name"],
                    "stopped",
                    action,
                    False,
                    msg,
                )
            return {"process_id": proc["id"], "status": "stopped", "action_taken": action, "detail": msg}

        target = proc["recovery_target"] or (proc["process_name"] if action == "systemctl_restart" else "")
        try:
            rec_status, rec_data = await send_encrypted_command(
                client,
                srv,
                "/api/v1/processes/recover",
                {"action_type": action, "target": target},
                timeout=30.0,
                log_plain=True,
            )
            if rec_status != 200:
                raise RuntimeError(str(rec_data.get("detail", rec_data)))
            rec_detail = str(rec_data.get("detail", "recovered"))
            await self.store.update_process_status(proc["id"], "recovered", rec_detail, now)
            await self.store.append_audit(
                srv["id"],
                srv["name"],
                "process/recover",
                {"process_id": proc["id"], "process_name": proc["process_name"], "action_type": action, "target": target},
                True,
                rec_detail,
            )
            if proc["save_log"]:
                await self.store.append_process_log(
                    srv["id"],
                    srv["name"],
                    proc["id"],
                    proc["process_name"],
                    "recovered",
                    action,
                    True,
                    rec_detail,
                )
            return {"process_id": proc["id"], "status": "recovered", "action_taken": action, "detail": rec_detail}
        except (httpx.RequestError, RuntimeError, ValueError) as exc:
            fail_msg = f"Recovery ({action}) failed for '{proc['process_name']}': {exc}"
            await self.store.update_process_status(proc["id"], "recovery_failed", fail_msg, now)
            await self.store.append_audit(
                srv["id"],
                srv["name"],
                "process/recover",
                {"process_id": proc["id"], "process_name": proc["process_name"], "action_type": action, "target": target},
                False,
                fail_msg,
            )
            if proc["save_log"]:
                await self.store.append_process_log(
                    srv["id"],
                    srv["name"],
                    proc["id"],
                    proc["process_name"],
                    "recovery_failed",
                    action,
                    False,
                    fail_msg,
                )
            return {"process_id": proc["id"], "status": "recovery_failed", "action_taken": action, "detail": fail_msg}
