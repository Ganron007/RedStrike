from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class HitlGate(str, Enum):
    """Privilege jumps that require human approval before execute."""

    DCSYNC = "dcsync"
    TICKET = "ticket"
    FOREST = "forest"
    PERSISTENCE = "persistence"
    ACL_WRITE = "acl_write"
    SITE_TAKEOVER = "site_takeover"


KNOWN_GATES = {g.value for g in HitlGate}


@dataclass
class EngagementState:
    engagement_id: str
    beachhead: str = "windows"
    operator: str = "provisioning"
    allow_mbr01_stage: bool = False
    approved_gates: list[str] = field(default_factory=list)
    status: str = "idle"  # idle | running | paused | complete
    pending_gate: str | None = None
    last_phase: str | None = None
    notes: str | None = None

    def is_approved(self, gate: str | HitlGate | None) -> bool:
        if gate is None:
            return True
        value = gate.value if isinstance(gate, HitlGate) else str(gate)
        return value in self.approved_gates

    def approve(self, gate: str | HitlGate, *, note: str | None = None) -> None:
        value = gate.value if isinstance(gate, HitlGate) else str(gate)
        if value not in KNOWN_GATES:
            raise ValueError(f"unknown HITL gate '{value}'; known={sorted(KNOWN_GATES)}")
        if value not in self.approved_gates:
            self.approved_gates.append(value)
        if self.pending_gate == value:
            self.pending_gate = None
            if self.status == "paused":
                self.status = "running"
        if note:
            self.notes = note

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EngagementState:
        return cls(
            engagement_id=str(data["engagement_id"]),
            beachhead=str(data.get("beachhead") or "windows"),
            operator=str(data.get("operator") or "provisioning"),
            allow_mbr01_stage=bool(data.get("allow_mbr01_stage") or False),
            approved_gates=list(data.get("approved_gates") or []),
            status=str(data.get("status") or "idle"),
            pending_gate=data.get("pending_gate"),
            last_phase=data.get("last_phase"),
            notes=data.get("notes"),
        )


class EngagementStore:
    """Persists engagement state next to the credential ledger."""

    def __init__(self, engagement_id: str, *, root: Path | None = None) -> None:
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
        self.path = self.dir / "state.json"

    def load(self) -> EngagementState | None:
        if not self.path.is_file():
            return None
        return EngagementState.from_dict(json.loads(self.path.read_text(encoding="utf-8")))

    def save(self, state: EngagementState) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state.to_dict(), indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def get_or_create(
        self,
        *,
        beachhead: str = "windows",
        allow_mbr01_stage: bool = False,
        operator: str = "provisioning",
    ) -> EngagementState:
        existing = self.load()
        if existing is not None:
            return existing
        state = EngagementState(
            engagement_id=self.engagement_id,
            beachhead=beachhead,
            operator=operator,
            allow_mbr01_stage=allow_mbr01_stage,
            status="idle",
        )
        self.save(state)
        return state
