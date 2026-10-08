from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redstrike.runtime import crypto

logger = logging.getLogger(__name__)


@dataclass
class Credential:
    name: str
    username: str
    password: str | None = None
    nt_hash: str | None = None
    domain: str | None = None
    source: str = "seed"
    notes: str | None = None
    #: password | nt_hash | ticket | cert | token | federated (Phase 9: tokens)
    cred_type: str | None = None
    #: Token/PFX material that is neither a password nor an NT hash.
    token: str | None = None
    expires_at: str | None = None

    def has_material(self) -> bool:
        return bool(self.password or self.nt_hash or self.token)


class MissingCredentialError(LookupError):
    """Fail-closed: required credential not in engagement ledger."""


class CredentialLedger:
    """Per-engagement credential store under ~/.redstrike/engagements/<id>/creds.json.

    The file carries an HMAC-SHA256 seal over its contents (see
    ``redstrike/runtime/crypto.py``): tampering is detected and fails closed
    unless ``REDSTRIKE_LEDGER_UNVERIFIED=1`` is set for recovery. With the
    optional ``cryptography`` package and ``REDSTRIKE_LEDGER_ENCRYPT=1`` the
    ledger is additionally encrypted at rest (AES-256-GCM).
    """

    def __init__(
        self,
        engagement_id: str,
        *,
        root: Path | None = None,
    ) -> None:
        if not engagement_id or "/" in engagement_id or "\\" in engagement_id:
            raise ValueError("engagement_id must be a simple identifier")
        if root is not None:
            base = Path(root)
        else:
            env_home = os.environ.get("REDSTRIKE_HOME")
            base = (
                Path(env_home) / "engagements"
                if env_home
                else Path.home() / ".redstrike" / "engagements"
            )
        self.engagement_id = engagement_id
        self.dir = Path(base) / engagement_id
        self.path = self.dir / "creds.json"
        self._creds: dict[str, Credential] = {}
        self._key: bytes | None = None
        if self.path.is_file():
            self._load()

    def _key_bytes(self, *, create: bool) -> bytes:
        if self._key is None or create:
            self._key = crypto.load_key(self.dir, create=create)
        return self._key

    def _load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise crypto.IntegrityError(
                f"ledger {self.path} is not a sealed JSON object (legacy or corrupt)"
            )

        integrity = raw.get("integrity")
        is_encrypted = "encrypted" in raw
        if is_encrypted:
            # The seal covers the CIPHERTEXT envelope; verify before decrypting.
            if not integrity and not crypto.unverified_allowed():
                raise crypto.IntegrityError(
                    f"encrypted ledger {self.path} has no integrity seal (tamper or downgrade)"
                )
            if integrity:
                try:
                    key = self._key_bytes(create=False)
                    if not crypto.verify(raw["encrypted"], integrity, key=key):
                        raise crypto.IntegrityError(
                            f"ledger {self.path} failed HMAC verification (tampered or wrong key)"
                        )
                except crypto.IntegrityError:
                    if not crypto.unverified_allowed():
                        raise
                    logger.warning(
                        "ledger %s failed integrity verification; loading UNVERIFIED (operator override)",
                        self.path,
                    )
            plaintext = crypto.decrypt_text(raw["encrypted"], key=self._key_bytes(create=False))
            raw = json.loads(plaintext) if plaintext else {}

        items = raw.get("credentials", raw) if isinstance(raw, dict) else {}

        key_exists = (self.dir / "key.bin").is_file() or bool(os.environ.get("REDSTRIKE_LEDGER_KEY"))

        if not is_encrypted:
            if integrity:
                try:
                    key = self._key_bytes(create=False)
                    if not crypto.verify(items, integrity, key=key):
                        raise crypto.IntegrityError(
                            f"ledger {self.path} failed HMAC verification (tampered or wrong key)"
                        )
                except crypto.IntegrityError:
                    if not crypto.unverified_allowed():
                        raise
                    logger.warning(
                        "ledger %s failed integrity verification; loading UNVERIFIED (operator override)",
                        self.path,
                    )
            else:
                if key_exists and not crypto.unverified_allowed():
                    raise crypto.IntegrityError(
                        f"ledger {self.path} has no integrity seal on a keyed engagement (tamper or downgrade)"
                    )
                if raw:
                    logger.warning(
                        "ledger %s has no integrity seal; loading under legacy/unverified policy",
                        self.path,
                    )

        self._creds = {}
        if isinstance(items, dict):
            for name, payload in items.items():
                self._creds[name] = _from_payload(name, payload)
        elif isinstance(items, list):
            for payload in items:
                name = str(payload["name"])
                self._creds[name] = _from_payload(name, payload)

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        key = self._key_bytes(create=True)
        credentials = {name: asdict(cred) for name, cred in sorted(self._creds.items())}
        payload: dict[str, Any] = {
            "engagement_id": self.engagement_id,
            "credentials": credentials,
        }
        envelope: dict[str, Any] = {"engagement_id": self.engagement_id}
        if crypto.encryption_requested():
            if not crypto.encryption_available():
                raise RuntimeError(
                    "REDSTRIKE_LEDGER_ENCRYPT requested but 'cryptography' package is unavailable"
                )
            encrypted = crypto.encrypt_text(json.dumps(payload), key=key)
            if encrypted is None:
                raise RuntimeError("Failed to produce encrypted ledger envelope")
            envelope["encrypted"] = encrypted
            envelope["integrity"] = crypto.seal(encrypted, key=key)
        if "encrypted" not in envelope:
            envelope["credentials"] = credentials
            envelope["integrity"] = crypto.seal(credentials, key=key)
        tmp = self.dir / f"creds.{uuid.uuid4().hex}.tmp"
        tmp.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    @classmethod
    def import_legacy(
        cls,
        source_path: Path | str,
        engagement_id: str,
        *,
        root: Path | None = None,
    ) -> CredentialLedger:
        """Explicitly import an unsealed legacy ledger with documented provenance."""
        src = Path(source_path)
        if not src.is_file():
            raise FileNotFoundError(f"Source ledger file not found: {source_path}")
        ledger = cls(engagement_id, root=root)
        raw = json.loads(src.read_text(encoding="utf-8"))
        items = raw.get("credentials", raw) if isinstance(raw, dict) else {}
        ledger._creds = {}
        if isinstance(items, dict):
            for name, payload in items.items():
                ledger._creds[name] = _from_payload(name, payload)
        elif isinstance(items, list):
            for payload in items:
                name = str(payload["name"])
                ledger._creds[name] = _from_payload(name, payload)
        ledger.dir.mkdir(parents=True, exist_ok=True)
        marker = ledger.dir / ".legacy_import"
        marker.write_text(
            json.dumps({
                "source": str(src.resolve()),
                "imported_at": datetime.now(timezone.utc).isoformat(),
            }),
            encoding="utf-8",
        )
        ledger.save()
        return ledger

    def seed(self, credentials: list[dict[str, Any]] | dict[str, Any], *, overwrite: bool = False) -> int:
        added = 0
        if isinstance(credentials, dict) and "credentials" in credentials:
            credentials = credentials["credentials"]
        if isinstance(credentials, dict):
            iterable = [
                {**payload, "name": name} if isinstance(payload, dict) else payload
                for name, payload in credentials.items()
            ]
        else:
            iterable = list(credentials)

        for payload in iterable:
            name = str(payload["name"])
            if name in self._creds and not overwrite:
                continue
            self._creds[name] = _from_payload(name, payload)
            added += 1
        self.save()
        return added

    def put(self, cred: Credential) -> None:
        self._creds[cred.name] = cred
        self.save()

    def setdefault(self, cred: Credential) -> Credential:
        """Flow-preserving insert: never downgrade an entry that already has
        material with a placeholder, but DO upgrade a placeholder when real
        material arrives (e.g. a seed name later resolved by a parser).
        """
        existing = self._creds.get(cred.name)
        if existing is None:
            self._creds[cred.name] = cred
            self.save()
            return cred
        if not existing.has_material() and cred.has_material():
            self._creds[cred.name] = cred
            self.save()
            return cred
        return existing

    def has(self, name: str) -> bool:
        return name in self._creds

    def get(self, name: str) -> Credential | None:
        return self._creds.get(name)

    def require(self, name: str) -> Credential:
        cred = self._creds.get(name)
        if cred is None:
            raise MissingCredentialError(
                f"credential '{name}' missing from engagement '{self.engagement_id}' "
                f"(fail-closed; seed ledger or earn via prior step)"
            )
        return cred

    def names(self) -> list[str]:
        return sorted(self._creds)


def _from_payload(name: str, payload: dict[str, Any]) -> Credential:
    return Credential(
        name=name,
        username=str(payload.get("username") or name),
        password=payload.get("password"),
        nt_hash=payload.get("nt_hash"),
        domain=payload.get("domain"),
        source=str(payload.get("source") or "seed"),
        notes=payload.get("notes"),
        cred_type=payload.get("cred_type"),
        token=payload.get("token"),
        expires_at=payload.get("expires_at"),
    )
