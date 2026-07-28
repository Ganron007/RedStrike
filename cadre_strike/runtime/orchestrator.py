from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cadre_strike.core.runner import CommandRunner, redact_argv
from cadre_strike.runtime.beachhead import Beachhead, BeachheadRouter, ExecutionPath, StepPlan
from cadre_strike.runtime.graph import (
    CampaignGraph,
    CampaignNode,
    load_campaign_graph,
    parse_branches,
    parse_phase_filter,
    resolve_graph_path,
)
from cadre_strike.runtime.preflight import PreflightResult, preflight as run_preflight
from cadre_strike.runtime.hitl import EngagementState, EngagementStore
from cadre_strike.runtime.intents import DEFAULT_REGISTRY, IntentRegistry, UnknownIntentError
from cadre_strike.runtime.ledger import Credential, CredentialLedger, MissingCredentialError


@dataclass
class StepResult:
    plan: StepPlan
    dry_run: bool
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    skipped: bool = False
    skip_reason: str | None = None
    error: str | None = None
    awaiting_approval: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.plan.node_id,
            "title": self.plan.title,
            "phase": self.plan.phase,
            "path": self.plan.path.value,
            "beachhead": self.plan.beachhead.value,
            "uses_ws01_exec": self.plan.uses_ws01_exec,
            "mechanism": self.plan.mechanism,
            "argv": redact_argv(self.plan.argv),
            "requires_cred": self.plan.requires_cred,
            "produces_cred": self.plan.produces_cred,
            "hitl_gate": self.plan.hitl_gate,
            "stub": self.plan.stub,
            "branch": self.plan.branch,
            "intent": self.plan.intent,
            "dry_run": self.dry_run,
            "return_code": self.return_code,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "awaiting_approval": self.awaiting_approval,
            "error": self.error,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exception_reason": self.plan.exception_reason,
        }


def _blocked_plan(
    node: CampaignNode,
    beachhead: Beachhead,
    path: ExecutionPath,
    *,
    mechanism: str = "blocked",
) -> StepPlan:
    return StepPlan(
        node_id=node.id,
        title=node.title,
        phase=node.phase,
        path=path,
        beachhead=beachhead,
        argv=[],
        uses_ws01_exec=False,
        mechanism=mechanism,
        script=node.script,
        requires_cred=node.requires_cred,
        produces_cred=node.produces_cred,
        hitl_gate=node.hitl_gate,
        stub=node.stub,
        branch=node.branch,
        intent=node.intent,
        pivot_to=node.pivot_to,
        produces_beachhead=node.produces_beachhead,
    )


class CampaignOrchestrator:
    """CampaignOrchestrator — graph + ledger + beachhead + HITL + typed intents."""

    PROFILE = "cadre-campaign"

    def __init__(
        self,
        *,
        engagement_id: str,
        beachhead: Beachhead | str,
        automation_root: Path | str,
        graph_path: Path | str | None = None,
        cadre_root: Path | str | None = None,
        ledger_root: Path | None = None,
        allow_mbr01_stage: bool = False,
        runner: CommandRunner | None = None,
        engagement_state: EngagementState | None = None,
        branches: str | set[str] | None = None,
        intents: IntentRegistry | None = None,
        prefer_script: bool = False,
    ) -> None:
        self.engagement_id = engagement_id
        self.beachhead = Beachhead(beachhead)
        self.automation_root = Path(automation_root)
        self.cadre_root = cadre_root
        resolved = resolve_graph_path(explicit=graph_path, cadre_root=cadre_root)
        self.graph_path = resolved
        self.graph: CampaignGraph = load_campaign_graph(resolved)
        self.ledger = CredentialLedger(engagement_id, root=ledger_root)
        self.store = EngagementStore(engagement_id, root=ledger_root)
        self.state = engagement_state or self.store.get_or_create(
            beachhead=self.beachhead.value,
            allow_mbr01_stage=allow_mbr01_stage,
        )
        self.router = BeachheadRouter(
            automation_root=self.automation_root,
            allow_mbr01_stage=allow_mbr01_stage or self.state.allow_mbr01_stage,
        )
        self.runner = runner or CommandRunner()
        self.allow_mbr01_stage = allow_mbr01_stage or self.state.allow_mbr01_stage
        if isinstance(branches, set):
            self.branches = branches or {"spine"}
        else:
            self.branches = parse_branches(branches)
        self.intents = intents or DEFAULT_REGISTRY
        self.prefer_script = prefer_script

    def parse_phases(self, phase_spec: str):
        return parse_phase_filter(phase_spec)

    def select_nodes(self, phase_spec: str) -> list[CampaignNode]:
        match = parse_phase_filter(phase_spec)
        return [
            node
            for node in self.graph.nodes_for_phases(match)
            if self.beachhead.value in node.beachheads and node.branch in self.branches
        ]

    def preflight(self, *, profile: str | None = None) -> PreflightResult:
        return run_preflight(
            self.branches,
            profile=profile,
            cadre_root=self.cadre_root,
        )

    def _plan_node(self, node: CampaignNode) -> StepPlan:
        argv_override: list[str] | None = None
        use_intent = bool(node.intent) and not self.prefer_script
        if use_intent:
            argv_override = self.intents.build(
                node.intent or "",
                node.intent_args,
                ledger=self.ledger,
                cred_name=node.cred or node.requires_cred,
            )
        return self.router.plan_step(
            node_id=node.id,
            title=node.title,
            phase=node.phase,
            declared_path=node.path,
            beachhead=self.beachhead,
            script=node.script,
            requires_cred=node.requires_cred,
            produces_cred=node.produces_cred,
            hitl_gate=node.hitl_gate,
            stub=node.stub,
            branch=node.branch,
            intent=node.intent if use_intent else None,
            argv_override=argv_override,
        )

    def plan(self, phase_spec: str = "1-3") -> list[StepPlan]:
        plans: list[StepPlan] = []
        for node in self.select_nodes(phase_spec):
            if node.requires_cred and not node.stub:
                self.ledger.require(node.requires_cred)
            plans.append(self._plan_node(node))
        return plans

    def run(
        self,
        phase_spec: str = "1-3",
        *,
        dry_run: bool = True,
        stop_on_hitl: bool = True,
    ) -> list[StepResult]:
        results: list[StepResult] = []
        self.state.last_phase = phase_spec
        self.state.status = "running"
        pending: str | None = None

        for node in self.select_nodes(phase_spec):
            default_path = (
                ExecutionPath.WS01
                if self.beachhead is Beachhead.WINDOWS
                else ExecutionPath.LINUX60
            )

            if node.stub:
                plan = self.router.plan_step(
                    node_id=node.id,
                    title=node.title,
                    phase=node.phase,
                    declared_path=node.path,
                    beachhead=self.beachhead,
                    script=node.script,
                    requires_cred=node.requires_cred,
                    produces_cred=node.produces_cred,
                    hitl_gate=node.hitl_gate,
                    stub=True,
                    branch=node.branch,
                    intent=node.intent,
                )
                results.append(
                    StepResult(
                        plan=plan,
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason="stub — not yet automated (graph placeholder)",
                    )
                )
                continue

            if node.hitl_gate and not self.state.is_approved(node.hitl_gate):
                # Preview without resolving intent/creds (approval may precede seed).
                plan = self.router.plan_step(
                    node_id=node.id,
                    title=node.title,
                    phase=node.phase,
                    declared_path=node.path,
                    beachhead=self.beachhead,
                    script=node.script,
                    requires_cred=node.requires_cred,
                    produces_cred=node.produces_cred,
                    hitl_gate=node.hitl_gate,
                    stub=False,
                    branch=node.branch,
                    intent=node.intent,
                )
                results.append(
                    StepResult(
                        plan=plan,
                        dry_run=dry_run,
                        skipped=True,
                        awaiting_approval=True,
                        skip_reason=(
                            f"HITL gate '{node.hitl_gate}' — approve with "
                            f"redstrike-campaign approve --gate {node.hitl_gate} --engage {self.engagement_id}"
                        ),
                    )
                )
                if pending is None:
                    pending = node.hitl_gate
                # Never execute unapproved gates; dry-run lists them as GATE and continues.
                if stop_on_hitl and not dry_run:
                    break
                continue

            try:
                if node.requires_cred:
                    self.ledger.require(node.requires_cred)
                plan = self._plan_node(node)
            except UnknownIntentError as exc:
                results.append(
                    StepResult(
                        plan=_blocked_plan(node, self.beachhead, default_path, mechanism="bad-intent"),
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason=str(exc),
                        error=str(exc),
                    )
                )
                continue
            except TypeError as exc:
                results.append(
                    StepResult(
                        plan=_blocked_plan(node, self.beachhead, default_path, mechanism="bad-intent-args"),
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason=f"intent args error: {exc}",
                        error=str(exc),
                    )
                )
                continue
            except MissingCredentialError as exc:
                results.append(
                    StepResult(
                        plan=_blocked_plan(node, self.beachhead, default_path),
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason=str(exc),
                        error=str(exc),
                    )
                )
                continue
            except PermissionError as exc:
                results.append(
                    StepResult(
                        plan=_blocked_plan(node, self.beachhead, ExecutionPath.STAGE_MBR01),
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason=str(exc),
                        error=str(exc),
                    )
                )
                continue

            if dry_run:
                results.append(StepResult(plan=plan, dry_run=True, return_code=0))
                continue

            completed = self.runner.run(plan.argv)
            if completed.success and node.produces_cred and not self.ledger.has(node.produces_cred):
                self.ledger.put(
                    Credential(
                        name=node.produces_cred,
                        username=node.produces_cred,
                        source=f"earned:{node.id}",
                        notes="placeholder — set password after crack/capture",
                    )
                )
            results.append(
                StepResult(
                    plan=plan,
                    dry_run=False,
                    return_code=completed.return_code,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    error=None if completed.success else (completed.stderr or "step failed"),
                )
            )

        if pending:
            self.state.pending_gate = pending
            self.state.status = "paused"
        else:
            self.state.pending_gate = None
            self.state.status = "complete" if results else "idle"
        self.store.save(self.state)
        return results

    def summary(self, results: list[StepResult]) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "profile": self.PROFILE,
            "beachhead": self.beachhead.value,
            "graph": str(self.graph_path),
            "graph_name": self.graph.name,
            "allow_mbr01_stage": self.allow_mbr01_stage,
            "ledger_creds": self.ledger.names(),
            "state": self.state.to_dict(),
            "steps": [r.to_dict() for r in results],
            "ws01_exec_count": sum(1 for r in results if r.plan.uses_ws01_exec and not r.skipped),
            "linux_direct_count": sum(
                1 for r in results if r.plan.mechanism == "direct-linux60" and not r.skipped
            ),
            "mbr01_count": sum(
                1 for r in results if r.plan.path is ExecutionPath.STAGE_MBR01 and not r.skipped
            ),
            "awaiting_approval_count": sum(1 for r in results if r.awaiting_approval),
            "stub_count": sum(1 for r in results if r.plan.stub and r.skipped),
            "branches": sorted(self.branches),
            "intent_count": sum(1 for r in results if r.plan.intent and not r.skipped),
        }
