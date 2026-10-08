from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
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
    CLOUD_TAKEOVER = "cloud_takeover"  # Phase 9: Entra/cloud identity takeover


KNOWN_GATES = {g.value for g in HitlGate}


def ungated_requested() -> bool:
    """Opt-in ungated mode: ``REDSTRIKE_UNGATED=1``, ``REDSTRIKE_PROFILE=autonomous``, or CLI/API ``--profile autonomous``."""
    if os.environ.get("REDSTRIKE_UNGATED", "").strip().lower() in {"1", "true", "yes"}:
        return True
    profile = os.environ.get("REDSTRIKE_PROFILE", "").strip().lower()
    return profile in {"autonomous", "campaign", "lab-ungated"}


def hitl_required(profile: str | None = None, policy: Any = None) -> bool:
    """HITL is active for 'gated' profile (default). 'autonomous' profile runs ungated under scope.

    Set ``REDSTRIKE_REQUIRE_HITL=1`` to force human approval gates unconditionally.
    """
    if os.environ.get("REDSTRIKE_REQUIRE_HITL", "").strip() == "1":
        return True
    if policy is not None and getattr(policy, "ungated", False):
        return False
    if profile is not None:
        p = profile.strip().lower()
        if p in {"autonomous", "campaign", "lab-ungated"}:
            return False
        if p in {"gated", "standalone", "lab-readonly"}:
            return True
    return not ungated_requested()


@dataclass
class EngagementState:
    engagement_id: str
    beachhead: str = "windows"
    operator: str = "linux"
    allow_stage: bool = False
    approved_gates: list[str] = field(default_factory=list)
    status: str = "idle"  # idle | running | paused | complete
    pending_gate: str | None = None
    last_phase: str | None = None
    notes: str | None = None
    #: Append-only audit trail of explicit operator approvals: {gate, note, ts}.
    approvals: list[dict[str, str]] = field(default_factory=list)
    #: Node ids verified live in this engagement (node_id -> {verified_at, phase,
    #: intent}) — enables `--resume` to skip already-verified steps.
    completed_nodes: dict[str, dict[str, str]] = field(default_factory=dict)
    #: Every live execution attempt (node_id -> {at, verified}). Unverified
    #: attempts on non-idempotent nodes refuse automatic re-runs under --resume.
    attempted_nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: Audit trail of credential reveals ({name, ts}) — UI/API reveals are loud.
    reveals: list[dict[str, str]] = field(default_factory=list)
    revision: int = 0
    #: Process-local approvals (autonomous/ungated profiles). NEVER persisted:
    #: a later run in a gated profile must not inherit phantom approvals.
    _auto_approved: set[str] = field(default_factory=set, repr=False, compare=False)

    def is_approved(self, gate: str | HitlGate | None) -> bool:
        if gate is None:
            return True
        value = gate.value if isinstance(gate, HitlGate) else str(gate)
        return value in self.approved_gates or value in self._auto_approved

    def approve(
        self,
        gate: str | HitlGate,
        *,
        note: str | None = None,
        persist: bool = True,
    ) -> None:
        """Record a gate approval.

        ``persist=False`` records an autonomous/ungated auto-approval for this
        process only (see ``_auto_approved``); it is deliberately excluded from
        ``to_dict()`` so engagement state on disk never carries it.
        """
        value = gate.value if isinstance(gate, HitlGate) else str(gate)
        if value not in KNOWN_GATES:
            raise ValueError(f"unknown HITL gate '{value}'; known={sorted(KNOWN_GATES)}")
        if persist:
            if value not in self.approved_gates:
                self.approved_gates.append(value)
            self.approvals.append(
                {
                    "gate": value,
                    "note": note or "",
                    "ts": datetime.now(timezone.utc).isoformat(),
                }
            )
        else:
            self._auto_approved.add(value)
        if self.pending_gate == value:
            self.pending_gate = None
            if self.status == "paused":
                self.status = "running"
        if note:
            self.notes = note

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if not k.startswith("_")}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EngagementState:
        return cls(
            engagement_id=str(data["engagement_id"]),
            beachhead=str(data.get("beachhead") or "windows"),
            operator=str(data.get("operator") or "linux"),
            allow_stage=bool(data.get("allow_stage") or False),
            approved_gates=list(data.get("approved_gates") or []),
            status=str(data.get("status") or "idle"),
            pending_gate=data.get("pending_gate"),
            last_phase=data.get("last_phase"),
            notes=data.get("notes"),
            approvals=[dict(item) for item in (data.get("approvals") or []) if isinstance(item, dict)],
            completed_nodes={
                str(node_id): dict(entry)
                for node_id, entry in (data.get("completed_nodes") or {}).items()
                if isinstance(entry, dict)
            },
            attempted_nodes={
                str(node_id): dict(entry)
                for node_id, entry in (data.get("attempted_nodes") or {}).items()
                if isinstance(entry, dict)
            },
            reveals=[dict(item) for item in (data.get("reveals") or []) if isinstance(item, dict)],
            revision=int(data.get("revision") or 0),
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
        lock_path = self.dir / ".lock"
        lock_fd = open(lock_path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                try:
                    lock_fd.seek(0)
                    msvcrt.locking(lock_fd.fileno(), msvcrt.LK_LOCK, 1)
                except OSError:
                    pass
            else:
                import fcntl
                try:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                except OSError:
                    pass

            existing = self.load()
            if existing is not None:
                merged_gates = list(dict.fromkeys(existing.approved_gates + state.approved_gates))
                state.approved_gates = merged_gates

                seen_approvals = set()
                merged_approvals = []
                for a in existing.approvals + state.approvals:
                    key = (a.get("gate"), a.get("note"), a.get("ts"))
                    if key not in seen_approvals:
                        seen_approvals.add(key)
                        merged_approvals.append(a)
                state.approvals = merged_approvals

                merged_completed = dict(existing.completed_nodes)
                merged_completed.update(state.completed_nodes)
                state.completed_nodes = merged_completed

                merged_attempted = dict(existing.attempted_nodes)
                merged_attempted.update(state.attempted_nodes)
                state.attempted_nodes = merged_attempted

                seen_reveals = set()
                merged_reveals = []
                for r in existing.reveals + state.reveals:
                    key = (r.get("name"), r.get("ts"))
                    if key not in seen_reveals:
                        seen_reveals.add(key)
                        merged_reveals.append(r)
                state.reveals = merged_reveals

                state.revision = max(state.revision, existing.revision) + 1
            else:
                state.revision = max(state.revision, 0) + 1

            tmp = self.dir / f"state.{uuid.uuid4().hex}.tmp"
            tmp.write_text(json.dumps(state.to_dict(), indent=2) + "\n", encoding="utf-8")
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        finally:
            if os.name == "nt":
                import msvcrt
                try:
                    lock_fd.seek(0)
                    msvcrt.locking(lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl
                try:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            lock_fd.close()

    def get_or_create(
        self,
        *,
        beachhead: str = "windows",
        allow_stage: bool = False,
        operator: str = "linux",
    ) -> EngagementState:
        existing = self.load()
        if existing is not None:
            return existing
        state = EngagementState(
            engagement_id=self.engagement_id,
            beachhead=beachhead,
            operator=operator,
            allow_stage=allow_stage,
            status="idle",
        )
        self.save(state)
        return state
