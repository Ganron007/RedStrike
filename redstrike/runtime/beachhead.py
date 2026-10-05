from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from redstrike.core.models import C2Backend, CallSpec


class Beachhead(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    SESSION = "session"


class OperatorMode(str, Enum):
    """Where the CampaignOrchestrator process runs.

    Distinct from Beachhead (attack-identity / preferred path):
    - linux: orchestrator on a Linux operator host → SSH into the Windows target
    - windows: orchestrator already on the Windows target host (no SSH wrap)
    - c2: orchestrator driving post-exploitation through C2 implants

    Pre-0.6 values ("provisioning", "ws01") parse as aliases.
    """

    LINUX = "linux"
    WINDOWS = "windows"
    C2 = "c2"

    @classmethod
    def _missing_(cls, value: object) -> OperatorMode | None:
        # Back-compat with engagements configured before the generic rename.
        return {"provisioning": cls.LINUX, "ws01": cls.WINDOWS}.get(str(value).lower())


class ExecutionPath(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    DIRECT = "direct"
    STAGE = "stage"
    EXTERNAL = "external"
    C2_IMPLANT = "c2_implant"

    @classmethod
    def _missing_(cls, value: object) -> ExecutionPath | None:
        # Back-compat with graphs written before the generic rename.
        return {
            "ws01": cls.WINDOWS,
            "linux60": cls.LINUX,
            "stage_mbr01": cls.STAGE,
            "external60_phase0": cls.EXTERNAL,
        }.get(str(value).lower())


def detect_default_operator() -> OperatorMode:
    """Prefer the Windows target host when running on Windows; else the Linux host."""
    env = os.environ.get("REDSTRIKE_OPERATOR", "").strip().lower()
    if env:
        try:
            return OperatorMode(env)
        except ValueError:
            pass
    if sys.platform == "win32":
        return OperatorMode.WINDOWS
    return OperatorMode.LINUX


@dataclass(frozen=True)
class StepPlan:
    """Resolved invocation for one campaign graph node (shell=False argv or C2 CallSpec)."""

    node_id: str
    title: str
    phase: float
    path: ExecutionPath
    beachhead: Beachhead
    argv: list[str]
    uses_windows_exec: bool
    mechanism: str
    script: str
    requires_cred: str | None
    produces_cred: str | None
    exception_reason: str | None = None
    hitl_gate: str | None = None
    stub: bool = False
    branch: str = "spine"
    intent: str | None = None
    pivot_to: str | None = None
    produces_beachhead: str | None = None
    operator: OperatorMode = OperatorMode.LINUX
    call_spec: CallSpec | None = None
    timeout_seconds: int | None = None


class BeachheadRouter:
    """Route campaign steps: windows target primary, linux alt, stage exception-only, c2_implant."""

    def __init__(
        self,
        *,
        automation_root: Path,
        allow_stage: bool = False,
        bash: str = "bash",
        operator: OperatorMode | str = OperatorMode.LINUX,
        c2_enabled: bool = False,
        c2_backend: C2Backend | str = C2Backend.SLIVER,
        c2_session_id: str | None = None,
    ) -> None:
        self.automation_root = Path(automation_root)
        self.allow_stage = allow_stage
        self.bash = bash
        self.operator = OperatorMode(operator)
        self.c2_enabled = c2_enabled
        self.c2_backend = C2Backend(c2_backend) if isinstance(c2_backend, str) else c2_backend
        self.c2_session_id = c2_session_id

    def effective_path(
        self,
        *,
        declared_path: str,
        beachhead: Beachhead,
    ) -> ExecutionPath:
        declared = ExecutionPath(declared_path)

        if declared is ExecutionPath.C2_IMPLANT or beachhead is Beachhead.SESSION:
            return ExecutionPath.C2_IMPLANT

        if declared is ExecutionPath.STAGE:
            if not self.allow_stage:
                raise PermissionError(
                    "path stage is exception-only; pass allow_stage=True "
                    "or --allow-stage"
                )
            return declared

        if declared is ExecutionPath.EXTERNAL:
            return declared

        # Beachhead overrides spine default (graph usually declares windows).
        if beachhead is Beachhead.WINDOWS:
            return ExecutionPath.WINDOWS
        return ExecutionPath.LINUX

    def plan_step(
        self,
        *,
        node_id: str,
        title: str,
        phase: float,
        declared_path: str,
        beachhead: Beachhead,
        script: str,
        requires_cred: str | None = None,
        produces_cred: str | None = None,
        exception_reason: str | None = None,
        hitl_gate: str | None = None,
        stub: bool = False,
        branch: str = "spine",
        intent: str | None = None,
        argv_override: list[str] | None = None,
        pivot_to: str | None = None,
        produces_beachhead: str | None = None,
        timeout_seconds: int | None = None,
    ) -> StepPlan:
        path = self.effective_path(declared_path=declared_path, beachhead=beachhead)
        native = self.operator is OperatorMode.WINDOWS

        if stub and not argv_override and not intent:
            argv: list[str] = []
            mechanism = "stub"
            uses_windows_exec = False
        elif argv_override is not None:
            argv = list(argv_override)
            mechanism = f"intent:{intent}" if intent else "typed"
            # Intents on path windows: remote SSH only under the linux operator.
            uses_windows_exec = path is ExecutionPath.WINDOWS and not native
        elif script:
            script_path = (self.automation_root / script).resolve()
            argv = [self.bash, str(script_path)]
            if path is ExecutionPath.WINDOWS:
                if native:
                    mechanism = "local-windows"
                    uses_windows_exec = False
                else:
                    mechanism = "windows-exec"
                    uses_windows_exec = True
            elif path is ExecutionPath.LINUX:
                mechanism = "direct-linux"
                uses_windows_exec = False
            elif path is ExecutionPath.STAGE:
                mechanism = "stage"
                uses_windows_exec = False
            else:
                mechanism = "external"
                uses_windows_exec = False
        else:
            argv = []
            mechanism = "stub"
            uses_windows_exec = False

        return StepPlan(
            node_id=node_id,
            title=title,
            phase=phase,
            path=path,
            beachhead=beachhead,
            argv=argv,
            uses_windows_exec=uses_windows_exec if not stub else False,
            mechanism=mechanism,
            script=script,
            requires_cred=requires_cred,
            produces_cred=produces_cred,
            exception_reason=(
                exception_reason or "operator-approved stage"
                if path is ExecutionPath.STAGE and not stub
                else exception_reason
            ),
            hitl_gate=hitl_gate,
            stub=stub,
            branch=branch,
            intent=intent,
            pivot_to=pivot_to,
            produces_beachhead=produces_beachhead,
            operator=self.operator,
            timeout_seconds=timeout_seconds,
        )
