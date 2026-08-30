from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from redstrike.core.models import EngagementMode
from redstrike.core.policy import ScopePolicy
from redstrike.core.runner import CommandRunner, redact_argv
from redstrike.runtime.hitl import KNOWN_GATES
from redstrike.runtime.intents import DEFAULT_REGISTRY
from redstrike.runtime.session import CampaignSession
from redstrike.runtime.streams import resolve_stream

_INTENT_TARGET_KEYS = ("host", "dc", "server", "kdc_host", "kdc", "ca", "target")
_INTENT_DOMAIN_KEYS = ("domain",)


class CampaignStartRequest(BaseModel):
    engagement_id: str
    beachhead: str = "windows"
    operator: str | None = None
    allow_mbr01_stage: bool = False
    graph: str | None = None
    automation_root: str | None = None
    seed: str | None = None
    branches: str = "spine"
    profile: str | None = None


class CampaignApproveRequest(BaseModel):
    engagement_id: str
    gate: str
    note: str | None = None
    beachhead: str = "windows"
    operator: str | None = None
    allow_mbr01_stage: bool = False
    branches: str = "spine"


class CampaignRunRequest(BaseModel):
    engagement_id: str
    beachhead: str = "windows"
    operator: str | None = None
    phase: str = "1-3"
    dry_run: bool | None = None
    stop_on_hitl: bool | None = None
    allow_mbr01_stage: bool = False
    graph: str | None = None
    automation_root: str | None = None
    seed: str | None = None
    branches: str = "spine"
    profile: str | None = None
    prefer_script: bool = False
    nodes: str | None = None
    c2_enabled: bool = False
    c2_backend: str = "sliver"
    c2_session: str | None = None
    c2_endpoint: str | None = None


class C2ListSessionsRequest(BaseModel):
    backend: str = "sliver"
    endpoint: str | None = None


class C2ExecuteAssemblyRequest(BaseModel):
    backend: str = "sliver"
    session_id: str
    assembly: str
    args: list[str] = Field(default_factory=list)
    endpoint: str | None = None
    timeout_seconds: int = 120


class C2ShellRequest(BaseModel):
    backend: str = "sliver"
    session_id: str
    command: str
    endpoint: str | None = None
    timeout_seconds: int = 60


class C2PsExecRequest(BaseModel):
    backend: str = "sliver"
    session_id: str
    target: str
    service_name: str = "RedStrikeSvc"
    bin_path: str = ""
    endpoint: str | None = None
    timeout_seconds: int = 120


class IntentPreviewRequest(BaseModel):
    intent: str
    args: dict[str, Any] = Field(default_factory=dict)


class CampaignStatusRequest(BaseModel):
    engagement_id: str
    beachhead: str = "windows"
    operator: str | None = None
    branches: str = "spine"


class CampaignStreamRequest(BaseModel):
    engagement_id: str
    stream: str
    beachhead: str = "linux"
    operator: str | None = None
    dry_run: bool | None = None
    graph: str | None = None
    automation_root: str | None = None
    seed: str | None = None
    profile: str | None = None


class IntentExecuteRequest(BaseModel):
    intent: str
    args: dict[str, Any] = Field(default_factory=dict)
    mode: EngagementMode = EngagementMode.VALIDATE


def scope_from_intent_args(args: dict[str, Any]) -> tuple[str, str | None]:
    """Pick a host/DC from builder args so scope can be enforced (host before target)."""
    target: str | None = None
    for key in _INTENT_TARGET_KEYS:
        value = args.get(key)
        if value:
            target = str(value)
            break
    domain: str | None = None
    for key in _INTENT_DOMAIN_KEYS:
        value = args.get(key)
        if value:
            domain = str(value)
            break
    if not target:
        raise PermissionError(
            "intent args must include host/dc/server/target so scope can be enforced"
        )
    return target, domain


def resolve_run_flags(
    *,
    dry_run: bool | None,
    stop_on_hitl: bool | None,
    ungated: bool,
) -> tuple[bool, bool]:
    """Standalone defaults to dry-run + HITL stop. Ungated defaults to live, no gate."""
    resolved_dry = dry_run if dry_run is not None else (not ungated)
    resolved_stop = stop_on_hitl if stop_on_hitl is not None else (not ungated)
    return resolved_dry, resolved_stop


def _session(
    req: CampaignStartRequest
    | CampaignRunRequest
    | CampaignApproveRequest
    | CampaignStatusRequest
    | CampaignStreamRequest,
) -> CampaignSession:
    return CampaignSession(
        req.engagement_id,
        beachhead=getattr(req, "beachhead", "windows") or "windows",
        operator=getattr(req, "operator", None),
        automation_root=getattr(req, "automation_root", None),
        graph_path=getattr(req, "graph", None),
        allow_mbr01_stage=bool(getattr(req, "allow_mbr01_stage", False)),
        seed_path=getattr(req, "seed", None),
        branches=getattr(req, "branches", "spine") or "spine",
        prefer_script=bool(getattr(req, "prefer_script", False)),
        node_ids=getattr(req, "nodes", None),
        profile=getattr(req, "profile", None),
        c2_enabled=bool(getattr(req, "c2_enabled", False)),
        c2_backend=getattr(req, "c2_backend", "sliver"),
        c2_session_id=getattr(req, "c2_session", None),
        c2_endpoint=getattr(req, "c2_endpoint", None),
    )


def intent_preview(req: IntentPreviewRequest) -> dict[str, Any]:
    argv = DEFAULT_REGISTRY.build(req.intent, req.args)
    return {
        "intent": req.intent,
        "argv": redact_argv(argv),
        "known_intents": DEFAULT_REGISTRY.known(),
    }


def intent_execute(
    req: IntentExecuteRequest,
    *,
    policy: ScopePolicy,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    if not policy.ungated:
        raise PermissionError("intent execute requires --ungated (scope-gated lab mode)")
    target, domain = scope_from_intent_args(req.args)
    policy.assert_allowed(
        action="intent_execute",
        target=target,
        domain=domain,
        mode=req.mode,
    )
    argv = DEFAULT_REGISTRY.build(req.intent, req.args)
    result = (runner or CommandRunner()).run(argv)
    return {
        "intent": req.intent,
        "argv": redact_argv(argv),
        "return_code": result.return_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "success": result.success,
        "timed_out": result.timed_out,
        "target": target,
        "domain": domain,
    }


def campaign_start(req: CampaignStartRequest) -> dict[str, Any]:
    return _session(req).start()


def campaign_approve(req: CampaignApproveRequest) -> dict[str, Any]:
    if req.gate not in KNOWN_GATES:
        raise ValueError(f"unknown gate '{req.gate}'; known={sorted(KNOWN_GATES)}")
    return _session(req).approve(req.gate, note=req.note)


def campaign_run_phase(req: CampaignRunRequest, *, ungated: bool = False) -> dict[str, Any]:
    dry_run, stop_on_hitl = resolve_run_flags(
        dry_run=req.dry_run,
        stop_on_hitl=req.stop_on_hitl,
        ungated=ungated,
    )
    return _session(req).run_phase(
        req.phase,
        dry_run=dry_run,
        stop_on_hitl=stop_on_hitl,
        profile=req.profile,
    )


def campaign_status(req: CampaignStatusRequest) -> dict[str, Any]:
    return _session(req).status()


def campaign_stream(req: CampaignStreamRequest, *, ungated: bool = False) -> dict[str, Any]:
    spec = resolve_stream(req.stream)
    session = CampaignSession(
        req.engagement_id,
        beachhead=req.beachhead or spec["beachhead"],
        operator=req.operator,
        automation_root=req.automation_root,
        graph_path=req.graph,
        seed_path=req.seed,
        branches=spec["branch"],
        profile=req.profile,
    )
    dry_run, _ = resolve_run_flags(dry_run=req.dry_run, stop_on_hitl=None, ungated=ungated)
    data = session.run_phase(
        spec["phase"],
        dry_run=dry_run,
        stop_on_hitl=not ungated,
        profile=req.profile,
    )
    data["stream"] = req.stream.upper()
    return data


def c2_list_sessions(req: C2ListSessionsRequest) -> dict[str, Any]:
    from redstrike.c2 import get_c2_client
    client = get_c2_client(req.backend, endpoint=req.endpoint)
    sessions = client.list_sessions()
    return {
        "ok": True,
        "backend": req.backend,
        "sessions": [s.model_dump(mode="json") for s in sessions],
    }


def c2_execute_assembly(req: C2ExecuteAssemblyRequest) -> dict[str, Any]:
    from redstrike.c2 import get_c2_client
    client = get_c2_client(req.backend, endpoint=req.endpoint)
    res = client.execute_assembly(req.session_id, req.assembly, req.args, timeout_seconds=req.timeout_seconds)
    return {
        "ok": res.success,
        "return_code": res.return_code,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "duration_seconds": res.duration_seconds,
    }


def c2_shell(req: C2ShellRequest) -> dict[str, Any]:
    from redstrike.c2 import get_c2_client
    client = get_c2_client(req.backend, endpoint=req.endpoint)
    res = client.shell(req.session_id, req.command, timeout_seconds=req.timeout_seconds)
    return {
        "ok": res.success,
        "return_code": res.return_code,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "duration_seconds": res.duration_seconds,
    }


def c2_psexec(req: C2PsExecRequest) -> dict[str, Any]:
    from redstrike.c2 import get_c2_client
    client = get_c2_client(req.backend, endpoint=req.endpoint)
    res = client.psexec(req.session_id, req.target, req.service_name, req.bin_path, timeout_seconds=req.timeout_seconds)
    return {
        "ok": res.success,
        "return_code": res.return_code,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "duration_seconds": res.duration_seconds,
    }
