import base64
import binascii
import json
import os
import time
from functools import lru_cache
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_SALT = b"linux-access-control-hub-aead-v1"
_INFO = b"agent-controller-payload-encryption"


@lru_cache(maxsize=64)
def derive_aead_key(secret_token: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_SALT,
        info=_INFO,
    )
    return hkdf.derive(secret_token.encode("utf-8"))


def encrypt_payload(data: dict[str, Any], secret_token: str) -> str:
    """Encrypt a dictionary with AES-256-GCM and embed a timestamp."""
    envelope = {
        "ts": round(time.time(), 3),
        "data": data,
    }
    plaintext = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = AESGCM(derive_aead_key(secret_token)).encrypt(nonce, plaintext, None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_payload(
    encrypted_str: str,
    secret_token: str,
    max_age_sec: float | None = 300.0,
) -> dict[str, Any]:
    """Decrypt an AES-256-GCM token and optionally verify replay window."""
    try:
        raw = base64.urlsafe_b64decode(encrypted_str.encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid base64 encrypted payload") from exc

    if len(raw) < 28:
        raise ValueError("Encrypted payload too short")

    nonce, ciphertext = raw[:12], raw[12:]
    try:
        plaintext = AESGCM(derive_aead_key(secret_token)).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("Payload decryption failed (invalid key or tampered packet)") from exc

    try:
        envelope = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Decrypted payload is not valid JSON") from exc

    if not isinstance(envelope, dict) or "data" not in envelope:
        raise ValueError("Invalid encrypted envelope structure")

    if max_age_sec is not None:
        ts = float(envelope.get("ts", 0))
        if abs(time.time() - ts) > max_age_sec:
            raise ValueError("Encrypted payload expired (replay protection)")

    data = envelope["data"]
    if not isinstance(data, dict):
        raise ValueError("Decrypted payload data must be an object")
    return data
