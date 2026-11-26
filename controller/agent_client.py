import json
import re
from typing import Any

import httpx

from controller.crypto import decrypt_payload, encrypt_payload
from controller.logger import get_controller_logger

logger = get_controller_logger("controller.outbound")

_ENC_LINE_RE = re.compile(r"\benc=([A-Za-z0-9_\-=]+)")


async def send_encrypted_command(
    client: httpx.AsyncClient,
    srv: dict[str, Any],
    api_path: str,
    payload: dict[str, Any],
    timeout: float = 15.0,
    log_plain: bool = True,
) -> tuple[int, dict[str, Any]]:
    """Send AES-256-GCM encrypted command to Agent while logging full plaintext on Controller."""
    target_url = f"{srv['url']}{api_path}"
    token = srv["token"]

    if log_plain:
        logger.info(
            "[OUTBOUND_PLAIN] POST %s server=%s(%s) payload=%s",
            target_url,
            srv["name"],
            srv["id"],
            json.dumps(payload, ensure_ascii=False),
        )

    enc_req = encrypt_payload(payload, token)
    headers = {
        "X-Agent-Token": token,
        "X-Payload-Encrypted": "1",
    }

    try:
        resp = await client.post(
            target_url,
            headers=headers,
            json={"enc": enc_req},
            timeout=timeout,
        )
    except httpx.RequestError as exc:
        if log_plain:
            logger.error(
                "[OUTBOUND_ERR] POST %s server=%s(%s) error=%s",
                target_url,
                srv["name"],
                srv["id"],
                exc,
            )
        raise

    resp_data: dict[str, Any]
    content_type = resp.headers.get("content-type", "")
    if "application/json" in content_type:
        raw_json = resp.json()
        if isinstance(raw_json, dict) and (
            resp.headers.get("x-payload-encrypted") == "1"
            or (set(raw_json.keys()) == {"enc"} and isinstance(raw_json.get("enc"), str))
        ):
            resp_data = decrypt_payload(raw_json["enc"], token, max_age_sec=300.0)
        elif isinstance(raw_json, dict):
            resp_data = raw_json
        else:
            resp_data = {"detail": str(raw_json)}
    else:
        resp_data = {"detail": resp.text}

    if log_plain:
        if resp.status_code == 200:
            logger.info(
                "[OUTBOUND_OK] POST %s server=%s(%s) status=200 response=%s",
                target_url,
                srv["name"],
                srv["id"],
                json.dumps(resp_data, ensure_ascii=False),
            )
        else:
            logger.warning(
                "[OUTBOUND_FAIL] POST %s server=%s(%s) status=%d response=%s",
                target_url,
                srv["name"],
                srv["id"],
                resp.status_code,
                json.dumps(resp_data, ensure_ascii=False),
            )

    return resp.status_code, resp_data


def decrypt_agent_log_entry(entry: dict[str, Any], secret_token: str, decrypt: bool = True) -> dict[str, Any]:
    """Attach decrypted plaintext data to an encrypted Agent log entry."""
    item = dict(entry)
    if not decrypt:
        return item
    enc_val = item.get("enc")
    if not isinstance(enc_val, str):
        item["decrypted"] = None
        item["decrypt_error"] = "Missing 'enc' field"
        return item
    try:
        item["decrypted"] = decrypt_payload(enc_val, secret_token, max_age_sec=None)
    except ValueError as exc:
        item["decrypted"] = None
        item["decrypt_error"] = str(exc)
    return item


def decrypt_raw_log_line(raw_line: str, secret_token: str) -> dict[str, Any]:
    """Extract and decrypt ciphertext from a raw token, JSONL line, or [ENC_LOG] log line."""
    stripped = raw_line.strip()
    enc_candidate: str | None = None

    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict) and isinstance(obj.get("enc"), str):
                enc_candidate = obj["enc"]
        except json.JSONDecodeError:
            enc_candidate = None

    if enc_candidate is None:
        match = _ENC_LINE_RE.search(stripped)
        if match:
            enc_candidate = match.group(1)
        elif stripped and " " not in stripped:
            enc_candidate = stripped

    if not enc_candidate:
        return {"raw": raw_line, "decrypted": None, "error": "No encrypted token found"}

    try:
        plain = decrypt_payload(enc_candidate, secret_token, max_age_sec=None)
        return {"raw": raw_line, "enc": enc_candidate, "decrypted": plain, "error": None}
    except ValueError as exc:
        return {"raw": raw_line, "enc": enc_candidate, "decrypted": None, "error": str(exc)}
