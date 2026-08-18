from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class Credential:
    name: str
    username: str
    password: str | None = None
    nt_hash: str | None = None
    domain: str | None = None
    source: str = "seed"
    notes: str | None = None


class MissingCredentialError(LookupError):
    """Fail-closed: required credential not in engagement ledger."""


class CredentialLedger:
    """Per-engagement credential store under ~/.redstrike/engagements/<id>/creds.json."""

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
        if self.path.is_file():
            self._load()

    def _load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        items = raw.get("credentials", raw) if isinstance(raw, dict) else raw
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
        payload = {
            "engagement_id": self.engagement_id,
            "credentials": {name: asdict(cred) for name, cred in sorted(self._creds.items())},
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

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
    )
