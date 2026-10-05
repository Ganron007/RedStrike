"""Cryptographic integrity (and optional encryption) for engagement state.

The credential ledger and engagement approvals are sealed with HMAC-SHA256 so
tampering is detectable; AES-256-GCM encryption at rest is available when the
``cryptography`` package is installed AND ``REDSTRIKE_LEDGER_ENCRYPT=1``.

Key resolution (first hit wins):
  * ``REDSTRIKE_LEDGER_KEY`` — hex or raw text key material;
  * ``<engagement dir>/key.bin`` — 32 random bytes, created on first save.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

HMAC_ALGO = "hmac-sha256"
ENCRYPT_ALGO = "aes-256-gcm"


class IntegrityError(RuntimeError):
    """Fail-closed: stored state failed HMAC verification or cannot be decrypted."""


def unverified_allowed() -> bool:
    """Explicit operator escape hatch for legacy/tampered files during recovery."""
    return os.environ.get("REDSTRIKE_LEDGER_UNVERIFIED", "").strip().lower() in {"1", "true", "yes"}


def encryption_requested() -> bool:
    return os.environ.get("REDSTRIKE_LEDGER_ENCRYPT", "").strip().lower() in {"1", "true", "yes"}


def encryption_available() -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


def load_key(root: Path, *, create: bool) -> bytes:
    """Engagement key for integrity/encryption.

    ``create=True`` mints ``key.bin`` when nothing is configured (save path);
    ``create=False`` never touches the filesystem (load path).
    """
    env = os.environ.get("REDSTRIKE_LEDGER_KEY", "").strip()
    if env:
        try:
            material = bytes.fromhex(env)
        except ValueError:
            material = env.encode("utf-8")
        if material:
            return material
    key_path = Path(root) / "key.bin"
    if key_path.is_file():
        return key_path.read_bytes()
    if not create:
        raise IntegrityError(
            f"no ledger key available ({key_path} missing and REDSTRIKE_LEDGER_KEY unset)"
        )
    Path(root).mkdir(parents=True, exist_ok=True)
    material = os.urandom(32)
    key_path.write_bytes(material)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return material


def _canonical(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal(payload: Any, *, key: bytes) -> dict[str, str]:
    mac = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    return {"algo": HMAC_ALGO, "hmac": mac}


def verify(payload: Any, seal_block: dict[str, str] | None, *, key: bytes) -> bool:
    if not isinstance(seal_block, dict) or not seal_block.get("hmac"):
        return False
    if seal_block.get("algo") != HMAC_ALGO:
        return False
    expected = hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(seal_block["hmac"]), expected)


def _derive_enc_key(key: bytes) -> bytes:
    return hashlib.sha256(b"redstrike-ledger-enc-v1:" + key).digest()


def encrypt_text(text: str, *, key: bytes) -> dict[str, str] | None:
    """AES-256-GCM encrypt; ``None`` when the crypto extra is not installed."""
    if not encryption_available():
        return None
    import os as _os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = _os.urandom(12)
    ciphertext = AESGCM(_derive_enc_key(key)).encrypt(nonce, text.encode("utf-8"), None)
    return {
        "algo": ENCRYPT_ALGO,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_text(block: dict[str, str], *, key: bytes) -> str:
    if not isinstance(block, dict) or block.get("algo") != ENCRYPT_ALGO:
        raise IntegrityError("unsupported encrypted payload format")
    if not encryption_available():
        raise IntegrityError(
            "engagement ledger is encrypted at rest but the 'cryptography' package "
            "is not installed (pip install 'redstrike[crypto]' or cryptography)"
        )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = base64.b64decode(block["nonce"])
    ciphertext = base64.b64decode(block["ct"])
    try:
        plaintext = AESGCM(_derive_enc_key(key)).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise IntegrityError(f"ledger decryption failed (wrong key or tampered file): {exc}") from exc
    return plaintext.decode("utf-8")
