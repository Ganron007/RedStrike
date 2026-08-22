from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Beachhead(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"


class OperatorMode(str, Enum):
    """Where the CampaignOrchestrator process runs.

    Distinct from Beachhead (attack-identity / preferred path):
    - provisioning: orchestrator on a Linux operator host → SSH into the Windows beachhead
    - ws01: orchestrator already on the domain-joined Windows beachhead (no SSH wrap)
    """

    PROVISIONING = "provisioning"
    WS01 = "ws01"


class ExecutionPath(str, Enum):
    WS01 = "ws01"
    LINUX60 = "linux60"
    DIRECT = "direct"
    STAGE_MBR01 = "stage_mbr01"
    EXTERNAL60_PHASE0 = "external60_phase0"


def detect_default_operator() -> OperatorMode:
    """Prefer native ws01 when running on Windows; otherwise provisioning hybrid."""
    env = os.environ.get("REDSTRIKE_OPERATOR", "").strip().lower()
    if env in {m.value for m in OperatorMode}:
        return OperatorMode(env)
    if sys.platform == "win32":
        return OperatorMode.WS01
    return OperatorMode.PROVISIONING


@dataclass(frozen=True)
class StepPlan:
    """Resolved invocation for one campaign graph node (shell=False argv)."""

    node_id: str
    title: str
    phase: float
    path: ExecutionPath
    beachhead: Beachhead
    argv: list[str]
    uses_ws01_exec: bool
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
    operator: OperatorMode = OperatorMode.PROVISIONING


class BeachheadRouter:
    """Route campaign steps: ws01 primary, linux60 alt, stage_mbr01 exception-only."""

    def __init__(
        self,
        *,
        automation_root: Path,
        allow_mbr01_stage: bool = False,
        bash: str = "bash",
        operator: OperatorMode | str = OperatorMode.PROVISIONING,
    ) -> None:
        self.automation_root = Path(automation_root)
        self.allow_mbr01_stage = allow_mbr01_stage
        self.bash = bash
        self.operator = OperatorMode(operator)

    def effective_path(
        self,
        *,
        declared_path: str,
        beachhead: Beachhead,
    ) -> ExecutionPath:
        declared = ExecutionPath(declared_path)

        if declared is ExecutionPath.STAGE_MBR01:
            if not self.allow_mbr01_stage:
                raise PermissionError(
                    "path stage_mbr01 is exception-only; pass allow_mbr01_stage=True "
                    "or --allow-mbr01-stage"
                )
            return declared

        if declared is ExecutionPath.EXTERNAL60_PHASE0:
            return declared

        # Beachhead overrides spine default (graph usually declares ws01).
        if beachhead is Beachhead.WINDOWS:
            return ExecutionPath.WS01
        return ExecutionPath.LINUX60

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
    ) -> StepPlan:
        path = self.effective_path(declared_path=declared_path, beachhead=beachhead)
        native = self.operator is OperatorMode.WS01

        if stub and not argv_override and not intent:
            argv: list[str] = []
            mechanism = "stub"
            uses_ws01 = False
        elif argv_override is not None:
            argv = list(argv_override)
            mechanism = f"intent:{intent}" if intent else "typed"
            # Intents on path ws01: remote SSH only under provisioning operator.
            uses_ws01 = path is ExecutionPath.WS01 and not native
        elif script:
            script_path = (self.automation_root / script).resolve()
            argv = [self.bash, str(script_path)]
            if path is ExecutionPath.WS01:
                if native:
                    mechanism = "local-ws01"
                    uses_ws01 = False
                else:
                    mechanism = "ws01-exec"
                    uses_ws01 = True
            elif path is ExecutionPath.LINUX60:
                mechanism = "direct-linux60"
                uses_ws01 = False
            elif path is ExecutionPath.STAGE_MBR01:
                mechanism = "stage_mbr01"
                uses_ws01 = False
            else:
                mechanism = "external60_phase0"
                uses_ws01 = False
        else:
            argv = []
            mechanism = "stub"
            uses_ws01 = False

        return StepPlan(
            node_id=node_id,
            title=title,
            phase=phase,
            path=path,
            beachhead=beachhead,
            argv=argv,
            uses_ws01_exec=uses_ws01 if not stub else False,
            mechanism=mechanism,
            script=script,
            requires_cred=requires_cred,
            produces_cred=produces_cred,
            exception_reason=(
                exception_reason or "operator-approved mbr01 stage"
                if path is ExecutionPath.STAGE_MBR01 and not stub
                else exception_reason
            ),
            hitl_gate=hitl_gate,
            stub=stub,
            branch=branch,
            intent=intent,
            pivot_to=pivot_to,
            produces_beachhead=produces_beachhead,
            operator=self.operator,
        )
