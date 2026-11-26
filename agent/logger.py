import contextvars
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from agent.crypto import encrypt_payload

mutating_context: contextvars.ContextVar[bool] = contextvars.ContextVar("mutating_context", default=False)


def _get_encrypted_log_path() -> Path:
    default_jsonl = Path(__file__).resolve().parent / "logs" / "agent_encrypted.jsonl"
    return Path(os.getenv("AGENT_ENCRYPTED_LOG_FILE", str(default_jsonl)))


def get_agent_logger(name: str = "agent") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    level_name = os.getenv("AGENT_LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, level_name, logging.INFO))
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    default_log = Path(__file__).resolve().parent / "logs" / "agent.log"
    log_path = Path(os.getenv("AGENT_LOG_FILE", str(default_log)))
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as exc:
        logger.warning("Failed to initialize file logger at %s: %s", log_path, exc)

    return logger


def record_encrypted_agent_log(
    event: str,
    plain_data: dict[str, Any],
    secret_token: str | None = None,
) -> dict[str, Any]:
    """Encrypt command/log details so only ciphertext is stored on the Agent."""
    token = secret_token or os.getenv("AGENT_TOKEN", "dev-agent-token")
    enc_value = encrypt_payload(plain_data, token)
    entry = {
        "id": f"alog-{uuid.uuid4().hex[:10]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "enc": enc_value,
    }

    logger = get_agent_logger("agent.enclog")
    logger.info("[ENC_LOG] id=%s event=%s enc=%s", entry["id"], event, enc_value)

    jsonl_path = _get_encrypted_log_path()
    try:
        jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        with jsonl_path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        logger.warning("Failed to append encrypted log to %s: %s", jsonl_path, exc)

    return entry


def list_encrypted_agent_logs(limit: int = 100) -> list[dict[str, Any]]:
    """Return most recent encrypted log entries stored on the Agent."""
    jsonl_path = _get_encrypted_log_path()
    if not jsonl_path.exists():
        return []
    try:
        lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    entries: list[dict[str, Any]] = []
    safe_limit = max(1, min(limit, 500))
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict) and "enc" in item:
                entries.append(item)
                if len(entries) >= safe_limit:
                    break
        except json.JSONDecodeError:
            continue
    return entries
