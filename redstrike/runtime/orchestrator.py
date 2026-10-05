from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redstrike.c2 import get_c2_client
from redstrike.core.models import C2Backend, CallKind, CallSpec
from redstrike.core.policy import ScopePolicy, load_scope_policy
from redstrike.core.runner import CommandRunner, redact_argv
from redstrike.core.secrets import extract_secrets, scrub_output
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
    collect_cloud_targets,
    collect_scope_targets,
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
from redstrike.runtime.teardown import load_queue as load_teardown_queue
from redstrike.runtime.teardown import save_queue as save_teardown_queue
from redstrike.runtime.verify import VerifyOutcome, verify_step_output
from redstrike.runtime.windows_transport import argv_for_plan


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
            "uses_windows_exec": self.plan.uses_windows_exec,
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
            # Output is scrubbed for derived consumers (API/MCP/JSON summaries):
            # credential material stays available to the raw journal/evidence
            # paths. REDSTRIKE_RAW_OUTPUT=1 disables scrubbing locally.
            "stdout": scrub_output(self.stdout),
            "stderr": scrub_output(self.stderr),
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
    operator: OperatorMode = OperatorMode.LINUX,
) -> StepPlan:
    return StepPlan(
        node_id=node.id,
        title=node.title,
        phase=node.phase,
        path=path,
        beachhead=beachhead,
        argv=[],
        uses_windows_exec=False,
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
    success_json = None
    if node.success_json:
        success_json = (node.success_json.get("path", ""), node.success_json.get("equals", ""))
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
        success_json=success_json,
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
        allow_stage: bool = False,
        runner: CommandRunner | None = None,
        engagement_state: EngagementState | None = None,
        branches: str | set[str] | None = None,
        intents: IntentRegistry | None = None,
        prefer_script: bool = False,
        operator: OperatorMode | str = OperatorMode.LINUX,
        node_ids: str | tuple[str, ...] | None = None,
        c2_enabled: bool = False,
        c2_backend: C2Backend | str = C2Backend.SLIVER,
        c2_session_id: str | None = None,
        c2_endpoint: str | None = None,
        scope_path: str | None = None,
        scope_policy: ScopePolicy | None = None,
        resume: bool = False,
        stop_on_failure: bool = False,
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
            allow_stage=allow_stage,
            operator=self.operator.value,
        )
        self.c2_enabled = c2_enabled or (self.beachhead is Beachhead.SESSION)
        self.c2_backend_auto = (
            isinstance(c2_backend, str) and c2_backend.strip().lower() == "auto"
        )
        self.c2_backend = (
            C2Backend.SLIVER
            if self.c2_backend_auto
            else (C2Backend(c2_backend) if isinstance(c2_backend, str) else c2_backend)
        )
        self.c2_session_id = c2_session_id
        self.c2_endpoint = c2_endpoint
        self.scope_path = scope_path
        self.scope_policy = scope_policy or (load_scope_policy(scope_path) if scope_path else None)
        self.resume = resume
        self.stop_on_failure = stop_on_failure
        self.teardown = load_teardown_queue(self.store.dir / "teardown.json")

        self.router = BeachheadRouter(
            automation_root=self.automation_root,
            allow_stage=allow_stage or self.state.allow_stage,
            operator=self.operator,
            c2_enabled=self.c2_enabled,
            c2_backend=self.c2_backend,
            c2_session_id=self.c2_session_id,
        )
        self.runner = runner or CommandRunner(
            c2_client=(
                get_c2_client(self.c2_backend, endpoint=self.c2_endpoint)
                if self.c2_enabled and not self.c2_backend_auto
                else None
            )
        )
        self.allow_stage = allow_stage or self.state.allow_stage
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
        call_spec: CallSpec | None = None
        use_intent = bool(node.intent) and not self.prefer_script
        if use_intent:
            call_spec = self.intents.build_spec(
                node.intent or "",
                node.intent_args,
                ledger=self.ledger,
                cred_name=node.cred or node.requires_cred,
            )
            if self.c2_session_id and call_spec.kind == CallKind.C2 and not call_spec.session_id:
                call_spec.session_id = self.c2_session_id
            argv_override = call_spec.to_display_command()
            if call_spec.kind == CallKind.ARGV:
                call_spec = None

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
            stub=node.stub,
            branch=node.branch,
            intent=node.intent if use_intent else None,
            argv_override=argv_override,
            timeout_seconds=node.timeout_seconds,
        )
        if call_spec is not None:
            plan = StepPlan(
                node_id=plan.node_id,
                title=plan.title,
                phase=plan.phase,
                path=ExecutionPath.C2_IMPLANT if call_spec.kind == CallKind.C2 else plan.path,
                beachhead=plan.beachhead,
                argv=plan.argv,
                uses_windows_exec=plan.uses_windows_exec,
                mechanism=f"c2:{call_spec.c2_backend.value if call_spec.c2_backend else 'task'}" if call_spec.kind == CallKind.C2 else plan.mechanism,
                script=plan.script,
                requires_cred=plan.requires_cred,
                produces_cred=plan.produces_cred,
                exception_reason=plan.exception_reason,
                hitl_gate=plan.hitl_gate,
                stub=plan.stub,
                branch=plan.branch,
                intent=plan.intent,
                pivot_to=plan.pivot_to,
                produces_beachhead=plan.produces_beachhead,
                operator=plan.operator,
                call_spec=call_spec,
            )
        return plan

    def plan(self, phase_spec: str = "1-3") -> list[StepPlan]:
        plans: list[StepPlan] = []
        for node in self.select_nodes(phase_spec):
            if node.requires_cred and not node.stub:
                self.ledger.require(node.requires_cred)
            plans.append(self._plan_node(node))
        return plans

    # ------------------------------------------------------------- C2 resolve
    def _pick_backend_from_fleet(self) -> C2Backend | None:
        """First backend (in preference order) with a live session on the stack."""
        from redstrike.c2.stack import C2StackClient

        fleet = C2StackClient(endpoint=self.c2_endpoint).sessions()
        sessions = fleet.get("sessions") if isinstance(fleet, dict) else None
        if not sessions:
            return None
        preference = (
            C2Backend.SLIVER,
            C2Backend.HAVOC,
            C2Backend.ADAPTIX,
            C2Backend.MYTHIC,
            C2Backend.MERIDIAN,
        )
        for backend in preference:
            if any(
                s.get("backend") == backend.value and s.get("is_alive", True)
                for s in sessions
            ):
                return backend
        return None

    def _resolve_session_id(self) -> str | None:
        """First live session id for the active backend (adapter first, portal fallback)."""
        client = self.runner.c2_client
        if client is not None:
            try:
                live = [s for s in client.list_sessions() if s.is_alive]
            except Exception:  # noqa: BLE001 - adapter transport issues must not abort the run
                live = []
            if live:
                return live[0].id
        from redstrike.c2.stack import C2StackClient

        picked = C2StackClient(endpoint=self.c2_endpoint).select_session(self.c2_backend.value)
        return str(picked["id"]) if picked and picked.get("id") else None

    def _resolve_c2(self) -> None:
        """Resolve ``--c2-backend auto`` and a missing session id against the live stack.

        Auto mode picks the first framework with a live session; a missing
        session id is looked up so ``--c2`` works without manual ids. When the
        stack cannot be reached the configuration is left untouched and the
        steps surface their own adapter errors.
        """
        if not self.c2_enabled:
            return
        if self.c2_backend_auto:
            picked = self._pick_backend_from_fleet()
            if picked is not None:
                self.c2_backend = picked
        if self.runner.c2_client is None:
            self.runner.c2_client = get_c2_client(self.c2_backend, endpoint=self.c2_endpoint)
        self.router.c2_backend = self.c2_backend
        if not self.c2_session_id:
            self.c2_session_id = self._resolve_session_id()
            self.router.c2_session_id = self.c2_session_id
        self.activity.emit(
            "c2_resolved",
            engagement_id=self.engagement_id,
            backend=self.c2_backend.value,
            session_id=self.c2_session_id,
            auto_backend=self.c2_backend_auto,
        )

    # ------------------------------------------------------- run machinery
    def _ordered_nodes(self, nodes: list[CampaignNode]) -> list[CampaignNode]:
        """Stable topological order over `depends_on` (cycle-free: validated at load)."""
        by_id = {node.id: node for node in nodes}
        ordered: list[CampaignNode] = []
        placed: set[str] = set()

        def _place(node: CampaignNode) -> None:
            if node.id in placed:
                return
            for dep in node.depends_on:
                if dep in by_id:
                    _place(by_id[dep])
            placed.add(node.id)
            ordered.append(node)

        for node in nodes:
            _place(node)
        return ordered

    def _dependency_skip_reason(
        self,
        node: CampaignNode,
        selected_ids: set[str],
        outcomes: dict[str, str],
        *,
        preview: bool = False,
    ) -> str | None:
        """Why this node cannot run: unmet `depends_on` / `when` conditions.

        ``preview=True`` (dry runs) counts a dry-run dependency as satisfied so
        whole graphs can be previewed; live runs require a real verification.
        """
        satisfying = {"verified", "dry_run"} if preview else {"verified"}
        for dep in node.depends_on:
            if dep not in selected_ids:
                return f"dependency '{dep}' is not part of this selection"
            status = outcomes.get(dep)
            if status is None:
                return f"dependency '{dep}' has not run yet"
            if status not in satisfying:
                return f"dependency '{dep}' did not verify ({status})"
        when = node.when or {}
        for ref in when.get("verified", []):
            if ref not in selected_ids:
                return f"when.verified references '{ref}' outside this selection"
            if outcomes.get(ref) not in satisfying:
                return f"when.verified not met: '{ref}' is {outcomes.get(ref, 'not run')}"
        for ref in when.get("unverified", []):
            if ref not in selected_ids:
                return f"when.unverified references '{ref}' outside this selection"
            if outcomes.get(ref) == "verified":
                return f"when.unverified falsified: '{ref}' verified"
        for cred_name in when.get("cred", []):
            if not self.ledger.has(cred_name):
                return f"when.cred not met: credential '{cred_name}' missing from ledger"
        return None

    def _scope_block_reason(self, node: CampaignNode) -> str | None:
        """Target-scope gate for live execution (declared targets only).

        Host targets come from the node's `target`/`targets` and target-like
        intent args (see graph.TARGET_ARG_KEYS); cloud targets come from
        `tenant:`-style args and are checked against allowed_tenants /
        allowed_cloud_domains. Opaque script nodes must declare `target(s)` to
        be scope-checked. Fail closed: a policy that cannot check targets
        (none configured / empty allow-lists) blocks the node.
        """
        targets = collect_scope_targets(node)
        cloud_targets = collect_cloud_targets(node)
        if not targets and not cloud_targets:
            return None
        policy = self.scope_policy
        if policy is None:
            return (
                "live execution against target(s) "
                + ", ".join([*targets, *cloud_targets])
                + " requires a scope policy (pass --scope <file>)"
            )
        if targets and not (policy.allowed_targets or policy.allowed_domains or policy.require_scope):
            return (
                "live execution against target(s) "
                + ", ".join(targets)
                + " requires a scope policy (pass --scope <file> with allowed_targets)"
            )
        if cloud_targets and not policy.cloud_scope_configured():
            return (
                "live execution against tenant(s) "
                + ", ".join(cloud_targets)
                + " requires allowed_tenants/allowed_cloud_domains in the scope policy"
            )
        domain_raw = (node.intent_args or {}).get("domain")
        domain = str(domain_raw) if domain_raw else None
        for target in targets:
            try:
                policy.assert_target_in_scope(target, domain)
            except PermissionError as exc:
                return str(exc)
        for tenant in cloud_targets:
            try:
                policy.assert_cloud_scope(tenant)
            except PermissionError as exc:
                return str(exc)
        return None

    def _record_completed(self, node: CampaignNode, finished_at: str | None) -> None:
        self.state.completed_nodes[node.id] = {
            "verified_at": finished_at or _utc_now(),
            "phase": str(node.phase),
            "intent": node.intent or node.script or "",
        }

    def _record_attempt(self, node: CampaignNode, *, verified: bool) -> None:
        self.state.attempted_nodes[node.id] = {
            "at": _utc_now(),
            "verified": verified,
            "phase": str(node.phase),
        }

    def _clear_rerun_state(self, nodes: list[CampaignNode]) -> None:
        """Drop completion/attempt records for the selected nodes (`--rerun`)."""
        cleared = 0
        for node in nodes:
            if self.state.completed_nodes.pop(node.id, None) is not None:
                cleared += 1
            self.state.attempted_nodes.pop(node.id, None)
        if cleared:
            self.activity.emit(
                "rerun_cleared",
                engagement_id=self.engagement_id,
                nodes=cleared,
            )

    def _ledger_credential_from_output(
        self, node: CampaignNode, stdout: str, stderr: str
    ) -> Credential:
        """Real material when parseable, honest placeholder otherwise."""
        parsed = extract_secrets(f"{stdout}\n{stderr}")
        primary = (
            next((item for item in parsed if item.is_hash), None)
            or next((item for item in parsed if item.kind in {"jwt", "token"}), None)
            or (parsed[0] if parsed else None)
        )
        if primary is not None:
            token_material = primary.kind in {"jwt", "token"}
            return Credential(
                name=node.produces_cred or node.id,
                username=primary.username or (node.produces_cred or node.id),
                domain=primary.domain,
                nt_hash=None if token_material else primary.value,
                token=primary.value if token_material else None,
                cred_type="token" if token_material else "nt_hash",
                source=f"earned:{node.id}",
                notes=f"parsed {primary.kind} material from step output",
            )
        return Credential(
            name=node.produces_cred or node.id,
            username=node.produces_cred or node.id,
            source=f"earned:{node.id}",
            notes="placeholder — no credential material parsed from step output",
        )

    def run(
        self,
        phase_spec: str = "1-3",
        *,
        dry_run: bool = True,
        stop_on_hitl: bool = True,
        resume: bool | None = None,
        stop_on_failure: bool | None = None,
        rerun: bool = False,
    ) -> list[StepResult]:
        results: list[StepResult] = []
        do_resume = self.resume if resume is None else resume
        do_stop_on_failure = self.stop_on_failure if stop_on_failure is None else stop_on_failure
        self._resolve_c2()
        self.state.last_phase = phase_spec
        self.state.status = "running"
        pending: str | None = None
        selected = self._ordered_nodes(self.select_nodes(phase_spec))
        if rerun and not dry_run:
            self._clear_rerun_state(selected)
        selected_ids = {node.id for node in selected}
        outcomes: dict[str, str] = {}
        stopped_by: str | None = None
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
                ExecutionPath.WINDOWS
                if self.beachhead is Beachhead.WINDOWS
                else ExecutionPath.LINUX
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
                outcomes[node.id] = "skipped"
                continue

            dep_reason = self._dependency_skip_reason(node, selected_ids, outcomes, preview=dry_run)
            if dep_reason:
                self._push(results, 
                    _step(
                        _blocked_plan(
                            node, self.beachhead, default_path, mechanism="dependency", operator=self.operator
                        ),
                        node,
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason=dep_reason,
                        error=dep_reason,
                    )
                )
                outcomes[node.id] = "skipped"
                continue

            if not dry_run and do_resume and node.id in self.state.completed_nodes:
                prior = self.state.completed_nodes[node.id]
                reason = f"already verified at {prior.get('verified_at', '?')} (resume)"
                self._push(results, 
                    _step(
                        _blocked_plan(
                            node, self.beachhead, default_path, mechanism="resumed", operator=self.operator
                        ),
                        node,
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason=reason,
                    )
                )
                outcomes[node.id] = "verified"
                continue

            if not dry_run and do_resume and node.idempotent is False:
                attempt = self.state.attempted_nodes.get(node.id)
                if attempt is not None and not attempt.get("verified"):
                    # A partially-applied non-idempotent step must not silently
                    # run twice — operator investigates, then passes --rerun.
                    reason = (
                        f"previous attempt at {attempt.get('at', '?')} did not verify and "
                        "node is marked non-idempotent (idempotent: false) — pass --rerun to force"
                    )
                    self._push(results, 
                        _step(
                            _blocked_plan(
                                node, self.beachhead, default_path, mechanism="non-idempotent", operator=self.operator
                            ),
                            node,
                            dry_run=dry_run,
                            skipped=True,
                            skip_reason=reason,
                        )
                    )
                    outcomes[node.id] = "skipped"
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
                outcomes[node.id] = "awaiting"
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
                            node, self.beachhead, ExecutionPath.STAGE, operator=self.operator
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
                outcomes[node.id] = "dry_run"
                continue

            scope_reason = self._scope_block_reason(node)
            if scope_reason:
                # Fail closed: block the node AND stop — continuing past an
                # out-of-scope target would defeat the scope policy.
                self._push(results, 
                    _step(
                        _blocked_plan(
                            node, self.beachhead, default_path, mechanism="scope-block", operator=self.operator
                        ),
                        node,
                        dry_run=dry_run,
                        skipped=True,
                        skip_reason=scope_reason,
                        error=scope_reason,
                    )
                )
                outcomes[node.id] = "skipped"
                stopped_by = f"scope block on {node.id}: {scope_reason}"
                break

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
            command = argv_for_plan(plan)
            if plan.timeout_seconds:
                completed = self.runner.run(command, timeout_seconds=plan.timeout_seconds)
            else:
                completed = self.runner.run(command)
            finished = _utc_now()
            outcome = _verify_node(
                node,
                dry_run=False,
                return_code=completed.return_code,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
            if outcome.verified:
                outcomes[node.id] = "verified"
                self._record_completed(node, finished)
                self._record_attempt(node, verified=True)
                if node.produces_cred and not self.ledger.has(node.produces_cred):
                    # Parse REAL credential material out of the step output;
                    # fall back to an honest placeholder when nothing parsed.
                    self.ledger.put(
                        self._ledger_credential_from_output(node, completed.stdout, completed.stderr)
                    )
                if node.teardown and node.teardown.get("command"):
                    self.teardown.register(
                        name=node.id,
                        target=",".join(collect_scope_targets(node)) or "-",
                        command=list(node.teardown["command"]),
                        description=str(node.teardown["description"]),
                    )
                    save_teardown_queue(self.store.dir / "teardown.json", self.teardown)
                    self.activity.emit(
                        "teardown_registered",
                        engagement_id=self.engagement_id,
                        node_id=node.id,
                        description=str(node.teardown["description"]),
                    )
            else:
                outcomes[node.id] = "unverified"
                self._record_attempt(node, verified=False)
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

            if do_stop_on_failure and not step.verified:
                stopped_by = (
                    f"stop_on_failure: step {node.id} did not verify "
                    f"({step.verify_reason or step.error or 'no marker'})"
                )
                remaining = [
                    nxt for nxt in selected
                    if nxt.id not in {r.plan.node_id for r in results}
                ]
                for nxt in remaining:
                    self._push(results, 
                        _step(
                            _blocked_plan(
                                nxt, self.beachhead, default_path, mechanism="stopped", operator=self.operator
                            ),
                            nxt,
                            dry_run=dry_run,
                            skipped=True,
                            skip_reason=stopped_by,
                        )
                    )
                    outcomes[nxt.id] = "skipped"
                break

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
            stopped_by=stopped_by,
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
            "allow_stage": self.allow_stage,
            "ledger_creds": self.ledger.names(),
            "state": self.state.to_dict(),
            "steps": [r.to_dict() for r in results],
            "windows_exec_count": sum(1 for r in results if r.plan.uses_windows_exec and not r.skipped),
            "local_windows_count": sum(
                1 for r in results if r.plan.mechanism == "local-windows" and not r.skipped
            ),
            "linux_direct_count": sum(
                1 for r in results if r.plan.mechanism == "direct-linux" and not r.skipped
            ),
            "stage_count": sum(
                1 for r in results if r.plan.path is ExecutionPath.STAGE and not r.skipped
            ),
            "awaiting_approval_count": sum(1 for r in results if r.awaiting_approval),
            "stub_count": sum(1 for r in results if r.plan.stub and r.skipped),
            "verified_count": sum(1 for r in executed if r.verified),
            "unverified_count": sum(1 for r in executed if not r.verified),
            "branches": sorted(self.branches),
            "intent_count": sum(1 for r in results if r.plan.intent and not r.skipped),
        }
