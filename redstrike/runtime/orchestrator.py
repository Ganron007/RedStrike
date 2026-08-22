from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redstrike.core.runner import CommandRunner, redact_argv
from redstrike.runtime.activity import ActivityJournal, resolve_activity_log
from redstrike.runtime.beachhead import (
    Beachhead,
    BeachheadRouter,
    ExecutionPath,
    OperatorMode,
    StepPlan,
)
from redstrike.runtime.graph import (
    CampaignGraph,
    CampaignNode,
    load_campaign_graph,
    parse_branches,
    parse_node_ids,
    parse_phase_filter,
    resolve_graph_path,
)
from redstrike.runtime.hitl import EngagementState, EngagementStore, hitl_required
from redstrike.runtime.intents import DEFAULT_REGISTRY, IntentRegistry, UnknownIntentError
from redstrike.runtime.ledger import Credential, CredentialLedger, MissingCredentialError
from redstrike.runtime.preflight import PreflightResult
from redstrike.runtime.preflight import preflight as run_preflight
from redstrike.runtime.verify import VerifyOutcome, verify_step_output
from redstrike.runtime.ws01_transport import argv_for_plan


def _utc_now() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(now.microsecond / 1000):03d}Z"


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
    started_at: str | None = None
    finished_at: str | None = None
    verified: bool = False
    verify_status: str = "unverified"
    verify_reason: str = ""
    success_marker: str | None = None

    def __post_init__(self) -> None:
        now = _utc_now()
        if self.started_at is None:
            self.started_at = now
        if self.finished_at is None:
            self.finished_at = self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.plan.node_id,
            "title": self.plan.title,
            "phase": self.plan.phase,
            "path": self.plan.path.value,
            "beachhead": self.plan.beachhead.value,
            "operator": self.plan.operator.value,
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
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "verified": self.verified,
            "verify_status": self.verify_status,
            "verify_reason": self.verify_reason,
            "success_marker": self.success_marker,
        }


def _blocked_plan(
    node: CampaignNode,
    beachhead: Beachhead,
    path: ExecutionPath,
    *,
    mechanism: str = "blocked",
    operator: OperatorMode = OperatorMode.PROVISIONING,
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
        operator=operator,
    )


def _verify_node(
    node: CampaignNode,
    *,
    dry_run: bool,
    skipped: bool = False,
    stub: bool = False,
    awaiting_approval: bool = False,
    return_code: int | None = None,
    stdout: str = "",
    stderr: str = "",
    error: str | None = None,
) -> VerifyOutcome:
    return verify_step_output(
        node_id=node.id,
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        error=error,
        success_marker=node.success_marker,
        extra_fail_patterns=node.fail_patterns,
        expected_errors=node.expected_errors,
        dry_run=dry_run,
        skipped=skipped,
        stub=stub or node.stub,
        awaiting_approval=awaiting_approval,
    )


def _step(
    plan: StepPlan,
    node: CampaignNode,
    *,
    dry_run: bool,
    skipped: bool = False,
    skip_reason: str | None = None,
    awaiting_approval: bool = False,
    return_code: int | None = None,
    stdout: str = "",
    stderr: str = "",
    error: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
) -> StepResult:
    outcome = _verify_node(
        node,
        dry_run=dry_run,
        skipped=skipped,
        stub=plan.stub,
        awaiting_approval=awaiting_approval,
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        error=error,
    )
    result_error = error
    if not dry_run and not skipped and not awaiting_approval and not outcome.verified:
        result_error = outcome.reason if not error else f"{error}; {outcome.reason}"
    return StepResult(
        plan=plan,
        dry_run=dry_run,
        return_code=return_code,
        stdout=stdout,
        stderr=stderr,
        skipped=skipped,
        skip_reason=skip_reason,
        error=result_error,
        awaiting_approval=awaiting_approval,
        started_at=started_at,
        finished_at=finished_at,
        verified=outcome.verified,
        verify_status=outcome.status,
        verify_reason=outcome.reason,
        success_marker=outcome.marker,
    )


class CampaignOrchestrator:
    """CampaignOrchestrator — graph + ledger + beachhead + HITL + typed intents."""

    PROFILE = "campaign"

    def __init__(
        self,
        *,
        engagement_id: str,
        beachhead: Beachhead | str,
        automation_root: Path | str,
        graph_path: Path | str | None = None,
        ledger_root: Path | None = None,
        allow_mbr01_stage: bool = False,
        runner: CommandRunner | None = None,
        engagement_state: EngagementState | None = None,
        branches: str | set[str] | None = None,
        intents: IntentRegistry | None = None,
        prefer_script: bool = False,
        operator: OperatorMode | str = OperatorMode.PROVISIONING,
        node_ids: str | tuple[str, ...] | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        self.beachhead = Beachhead(beachhead)
        self.operator = OperatorMode(operator)
        self.automation_root = Path(automation_root)
        resolved = resolve_graph_path(explicit=graph_path)
        self.graph_path = resolved
        self.graph: CampaignGraph = load_campaign_graph(resolved)
        self.ledger = CredentialLedger(engagement_id, root=ledger_root)
        self.store = EngagementStore(engagement_id, root=ledger_root)
        self.state = engagement_state or self.store.get_or_create(
            beachhead=self.beachhead.value,
            allow_mbr01_stage=allow_mbr01_stage,
            operator=self.operator.value,
        )
        self.router = BeachheadRouter(
            automation_root=self.automation_root,
            allow_mbr01_stage=allow_mbr01_stage or self.state.allow_mbr01_stage,
            operator=self.operator,
        )
        self.runner = runner or CommandRunner()
        self.allow_mbr01_stage = allow_mbr01_stage or self.state.allow_mbr01_stage
        if isinstance(branches, set):
            self.branches = branches or {"spine"}
        else:
            self.branches = parse_branches(branches)
        self.intents = intents or DEFAULT_REGISTRY
        self.prefer_script = prefer_script
        if isinstance(node_ids, tuple):
            self.node_ids = node_ids
        else:
            self.node_ids = parse_node_ids(node_ids)
        self.activity = ActivityJournal(
            resolve_activity_log(engagement_id, ledger_dir=self.ledger.dir)
        )

    def parse_phases(self, phase_spec: str):
        return parse_phase_filter(phase_spec)

    def select_nodes(self, phase_spec: str) -> list[CampaignNode]:
        if self.node_ids is not None:
            by_id = {node.id: node for node in self.graph.nodes}
            unknown = [nid for nid in self.node_ids if nid not in by_id]
            if unknown:
                raise ValueError(f"unknown node id(s): {unknown}")
            wrong_beachhead = [
                nid
                for nid in self.node_ids
                if self.beachhead.value not in by_id[nid].beachheads
            ]
            if wrong_beachhead:
                raise ValueError(
                    f"nodes not valid for beachhead {self.beachhead.value}: {wrong_beachhead}"
                )
            return [by_id[nid] for nid in self.node_ids]
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
        )

    def _push(self, results: list[StepResult], result: StepResult) -> StepResult:
        if result.skipped:
            event = "step_skip"
        elif result.dry_run:
            event = "step_dry_run"
        else:
            event = "step_end"
        self.activity.emit(
            event,
            engagement_id=self.engagement_id,
            node_id=result.plan.node_id,
            title=result.plan.title,
            phase=result.plan.phase,
            branch=result.plan.branch,
            mechanism=result.plan.mechanism,
            dry_run=result.dry_run,
            skipped=result.skipped,
            skip_reason=result.skip_reason,
            verified=result.verified,
            verify_status=result.verify_status,
            return_code=result.return_code,
            started_at=result.started_at,
            finished_at=result.finished_at,
        )
        results.append(result)
        return result

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
        selected = self.select_nodes(phase_spec)
        self.activity.emit(
            "campaign_run_start",
            engagement_id=self.engagement_id,
            beachhead=self.beachhead.value,
            operator=self.operator.value,
            phase_spec=phase_spec,
            dry_run=dry_run,
            prefer_script=self.prefer_script,
            node_count=len(selected),
            graph=str(self.graph_path),
            activity_log=str(self.activity.path) if self.activity.path else None,
        )

        for node in selected:
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
                self._push(results, 
                    _step(
                        plan,
                        node,
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason="stub — not yet automated (graph placeholder)",
                    )
                )
                continue

            if hitl_required() and node.hitl_gate and not self.state.is_approved(node.hitl_gate):
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
                self._push(results, 
                    _step(
                        plan,
                        node,
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
                self._push(results, 
                    _step(
                        _blocked_plan(
                            node, self.beachhead, default_path, mechanism="bad-intent", operator=self.operator
                        ),
                        node,
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason=str(exc),
                        error=str(exc),
                    )
                )
                continue
            except TypeError as exc:
                self._push(results, 
                    _step(
                        _blocked_plan(
                            node,
                            self.beachhead,
                            default_path,
                            mechanism="bad-intent-args",
                            operator=self.operator,
                        ),
                        node,
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason=f"intent args error: {exc}",
                        error=str(exc),
                    )
                )
                continue
            except MissingCredentialError as exc:
                self._push(results, 
                    _step(
                        _blocked_plan(node, self.beachhead, default_path, operator=self.operator),
                        node,
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason=str(exc),
                        error=str(exc),
                    )
                )
                continue
            except PermissionError as exc:
                self._push(results, 
                    _step(
                        _blocked_plan(
                            node, self.beachhead, ExecutionPath.STAGE_MBR01, operator=self.operator
                        ),
                        node,
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason=str(exc),
                        error=str(exc),
                    )
                )
                continue

            if dry_run:
                self._push(results, _step(plan, node, dry_run=True, return_code=0))
                continue

            started = _utc_now()
            self.activity.emit(
                "step_start",
                engagement_id=self.engagement_id,
                node_id=node.id,
                title=node.title,
                phase=node.phase,
                branch=node.branch,
                mechanism=plan.mechanism,
                argv=plan.argv,
            )
            completed = self.runner.run(argv_for_plan(plan))
            finished = _utc_now()
            outcome = _verify_node(
                node,
                dry_run=False,
                return_code=completed.return_code,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
            if outcome.verified and node.produces_cred and not self.ledger.has(node.produces_cred):
                self.ledger.put(
                    Credential(
                        name=node.produces_cred,
                        username=node.produces_cred,
                        source=f"earned:{node.id}",
                        notes="placeholder — set password after crack/capture",
                    )
                )
            step = _step(
                plan,
                node,
                dry_run=False,
                return_code=completed.return_code,
                stdout=completed.stdout,
                stderr=completed.stderr,
                error=None if completed.success else (completed.stderr or "step failed"),
                started_at=started,
                finished_at=finished,
            )
            self._push(results, step)

        if pending:
            self.state.pending_gate = pending
            self.state.status = "paused"
        else:
            self.state.pending_gate = None
            self.state.status = "complete" if results else "idle"
        self.store.save(self.state)
        self.activity.emit(
            "campaign_run_end",
            engagement_id=self.engagement_id,
            status=self.state.status,
            pending_gate=pending,
            step_count=len(results),
        )
        return results

    def summary(self, results: list[StepResult]) -> dict[str, Any]:
        starts = [r.started_at for r in results if r.started_at]
        ends = [r.finished_at for r in results if r.finished_at]
        executed = [r for r in results if not r.dry_run and not r.skipped]
        return {
            "engagement_id": self.engagement_id,
            "profile": self.PROFILE,
            "beachhead": self.beachhead.value,
            "operator": self.operator.value,
            "graph": str(self.graph_path),
            "graph_name": self.graph.name,
            "activity_log": str(self.activity.path) if self.activity.path else None,
            "node_ids": list(self.node_ids) if self.node_ids else None,
            "started_at": min(starts) if starts else None,
            "finished_at": max(ends) if ends else None,
            "allow_mbr01_stage": self.allow_mbr01_stage,
            "ledger_creds": self.ledger.names(),
            "state": self.state.to_dict(),
            "steps": [r.to_dict() for r in results],
            "ws01_exec_count": sum(1 for r in results if r.plan.uses_ws01_exec and not r.skipped),
            "local_ws01_count": sum(
                1 for r in results if r.plan.mechanism == "local-ws01" and not r.skipped
            ),
            "linux_direct_count": sum(
                1 for r in results if r.plan.mechanism == "direct-linux60" and not r.skipped
            ),
            "mbr01_count": sum(
                1 for r in results if r.plan.path is ExecutionPath.STAGE_MBR01 and not r.skipped
            ),
            "awaiting_approval_count": sum(1 for r in results if r.awaiting_approval),
            "stub_count": sum(1 for r in results if r.plan.stub and r.skipped),
            "verified_count": sum(1 for r in executed if r.verified),
            "unverified_count": sum(1 for r in executed if not r.verified),
            "branches": sorted(self.branches),
            "intent_count": sum(1 for r in results if r.plan.intent and not r.skipped),
        }
