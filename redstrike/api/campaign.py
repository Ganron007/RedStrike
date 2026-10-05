from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from redstrike.core.models import EngagementMode
from redstrike.core.policy import ScopePolicy
from redstrike.core.runner import CommandRunner, redact_argv
from redstrike.core.secrets import scrub_output
from redstrike.runtime.graph import (
    collect_scope_targets,
    load_campaign_graph,
    resolve_graph_path,
)
from redstrike.runtime.hitl import KNOWN_GATES, EngagementStore
from redstrike.runtime.intents import DEFAULT_REGISTRY
from redstrike.runtime.ledger import CredentialLedger
from redstrike.runtime.session import CampaignSession
from redstrike.runtime.streams import resolve_stream

_INTENT_DOMAIN_KEYS = ("domain",)


class CampaignStartRequest(BaseModel):
    engagement_id: str
    beachhead: str = "windows"
    operator: str | None = None
    allow_stage: bool = False
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
    allow_stage: bool = False
    branches: str = "spine"


class CampaignRunRequest(BaseModel):
    engagement_id: str
    beachhead: str = "windows"
    operator: str | None = None
    phase: str = "1-3"
    dry_run: bool | None = None
    stop_on_hitl: bool | None = None
    allow_stage: bool = False
    graph: str | None = None
    automation_root: str | None = None
    seed: str | None = None
    branches: str = "spine"
    profile: str | None = None
    prefer_script: bool = False
    nodes: str | None = None
    resume: bool = False
    stop_on_failure: bool = False
    rerun: bool = False
    c2_enabled: bool = False
    c2_backend: str = "sliver"  # sliver | meridian | mythic | havoc | adaptix
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


def scope_from_intent_args(args: dict[str, Any]) -> tuple[str, str | None, list[str]]:
    """Every host/DC/target-like value in builder args so scope can be enforced.

    Returns ``(primary_target, domain, all_targets)`` — ALL targets are
    validated by callers (a single-key check missed secondary hosts such as
    ``dc_ip``).
    """
    from redstrike.runtime.graph import targets_from_args

    targets = targets_from_args(args)
    if not targets:
        raise PermissionError(
            "intent args must include host/dc/server/target so scope can be enforced"
        )
    domain: str | None = None
    for key in _INTENT_DOMAIN_KEYS:
        value = args.get(key)
        if value:
            domain = str(value)
            break
    return targets[0], domain, targets


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
    *,
    policy: ScopePolicy | None = None,
) -> CampaignSession:
    return CampaignSession(
        req.engagement_id,
        beachhead=getattr(req, "beachhead", "windows") or "windows",
        operator=getattr(req, "operator", None),
        automation_root=getattr(req, "automation_root", None),
        graph_path=getattr(req, "graph", None),
        allow_stage=bool(getattr(req, "allow_stage", False)),
        seed_path=getattr(req, "seed", None),
        branches=getattr(req, "branches", "spine") or "spine",
        prefer_script=bool(getattr(req, "prefer_script", False)),
        node_ids=getattr(req, "nodes", None),
        profile=getattr(req, "profile", None),
        c2_enabled=bool(getattr(req, "c2_enabled", False)),
        c2_backend=getattr(req, "c2_backend", "sliver"),
        c2_session_id=getattr(req, "c2_session", None),
        c2_endpoint=getattr(req, "c2_endpoint", None),
        scope_policy=policy,
        resume=bool(getattr(req, "resume", False)),
        stop_on_failure=bool(getattr(req, "stop_on_failure", False)),
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
    target, domain, targets = scope_from_intent_args(req.args)
    for candidate in targets:
        policy.assert_allowed(
            action="intent_execute",
            target=candidate,
            domain=domain,
            mode=req.mode,
        )
    argv = DEFAULT_REGISTRY.build(req.intent, req.args)
    result = (runner or CommandRunner()).run(argv)
    return {
        "intent": req.intent,
        "argv": redact_argv(argv),
        "return_code": result.return_code,
        "stdout": scrub_output(result.stdout),
        "stderr": scrub_output(result.stderr),
        "success": result.success,
        "timed_out": result.timed_out,
        "target": target,
        "targets": targets,
        "domain": domain,
    }


def campaign_start(req: CampaignStartRequest) -> dict[str, Any]:
    return _session(req).start()


def campaign_approve(req: CampaignApproveRequest) -> dict[str, Any]:
    if req.gate not in KNOWN_GATES:
        raise ValueError(f"unknown gate '{req.gate}'; known={sorted(KNOWN_GATES)}")
    return _session(req).approve(req.gate, note=req.note)


def campaign_run_phase(
    req: CampaignRunRequest, *, ungated: bool = False, policy: ScopePolicy | None = None
) -> dict[str, Any]:
    dry_run, stop_on_hitl = resolve_run_flags(
        dry_run=req.dry_run,
        stop_on_hitl=req.stop_on_hitl,
        ungated=ungated,
    )
    return _session(req, policy=policy).run_phase(
        req.phase,
        dry_run=dry_run,
        stop_on_hitl=stop_on_hitl,
        profile=req.profile,
        rerun=bool(req.rerun),
    )


def campaign_status(req: CampaignStatusRequest) -> dict[str, Any]:
    return _session(req).status()


def campaign_recommend(req: Any) -> dict[str, Any]:
    """Real next-best-action ranking from the engagement's own state.

    Ranks the unexecuted, non-stub graph nodes: nodes whose required
    credential is already in the ledger come first (actionable now); nodes
    blocked on a missing credential follow. No invented probabilities — every
    field is derived from the graph, the ledger, and `state.completed_nodes`.
    """
    graph_path = resolve_graph_path(explicit=getattr(req, "graph", None))
    graph = load_campaign_graph(graph_path)
    store = EngagementStore(req.engagement_id)
    state = store.load()
    if state is None:
        raise FileNotFoundError(f"engagement '{req.engagement_id}' not found at {store.dir}")
    ledger = CredentialLedger(req.engagement_id)

    completed = state.completed_nodes
    recommendations: list[dict[str, Any]] = []
    for node in graph.nodes:
        if node.stub or node.id in completed:
            continue
        blocked_by = None
        if node.requires_cred and not ledger.has(node.requires_cred):
            blocked_by = f"requires credential '{node.requires_cred}' (not yet in ledger)"
        recommendations.append(
            {
                "node_id": node.id,
                "phase": node.phase,
                "title": node.title,
                "intent": node.intent,
                "hitl_gate": node.hitl_gate,
                "targets": collect_scope_targets(node),
                "actionable": blocked_by is None,
                "blocked_by": blocked_by,
            }
        )
    recommendations.sort(key=lambda item: (not item["actionable"], item["phase"], item["node_id"]))
    limit = max(1, int(getattr(req, "limit", 3) or 3))
    return {
        "engagement_id": req.engagement_id,
        "objective": req.objective,
        "graph": str(graph_path),
        "graph_name": graph.name,
        "status": state.status,
        "pending_gate": state.pending_gate,
        "completed_nodes": sorted(completed),
        "ledger_creds": ledger.names(),
        "actionable_count": sum(1 for item in recommendations if item["actionable"]),
        "recommendations": recommendations[:limit],
    }


def campaign_stream(
    req: CampaignStreamRequest, *, ungated: bool = False, policy: ScopePolicy | None = None
) -> dict[str, Any]:
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
        scope_policy=policy,
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
        "stdout": scrub_output(res.stdout),
        "stderr": scrub_output(res.stderr),
        "duration_seconds": res.duration_seconds,
    }


def c2_shell(req: C2ShellRequest) -> dict[str, Any]:
    from redstrike.c2 import get_c2_client
    client = get_c2_client(req.backend, endpoint=req.endpoint)
    res = client.shell(req.session_id, req.command, timeout_seconds=req.timeout_seconds)
    return {
        "ok": res.success,
        "return_code": res.return_code,
        "stdout": scrub_output(res.stdout),
        "stderr": scrub_output(res.stderr),
        "duration_seconds": res.duration_seconds,
    }


def c2_psexec(req: C2PsExecRequest) -> dict[str, Any]:
    from redstrike.c2 import get_c2_client
    client = get_c2_client(req.backend, endpoint=req.endpoint)
    res = client.psexec(req.session_id, req.target, req.service_name, req.bin_path, timeout_seconds=req.timeout_seconds)
    return {
        "ok": res.success,
        "return_code": res.return_code,
        "stdout": scrub_output(res.stdout),
        "stderr": scrub_output(res.stderr),
        "duration_seconds": res.duration_seconds,
    }


# --------------------------------------------------------------------------
# C2Stack Flight Control surface (fleet, capability probe, builds, staging).
# Unlike /c2/* (single-session tasking via one backend adapter), these call
# the portal directly and cover every framework the stack runs.
# --------------------------------------------------------------------------
class C2StackRequest(BaseModel):
    endpoint: str | None = None


class C2StackSessionsRequest(C2StackRequest):
    backend: str | None = None


class C2StackBuildRequest(C2StackRequest):
    backend: str
    out: str | None = None
    # sliver
    kind: str = "session"
    c2_url: str | None = None
    target_os: str = "windows"
    arch: str = "amd64"
    retrieve: bool = False
    # havoc
    format: str | None = None
    listener: str | None = None
    sleep: str | int | None = None
    jitter: int = 0
    # adaptix
    agent: str = "beacon"
    ensure_listener: bool = False
    # mythic
    output_type: str = "WinExe"
    filename: str | None = None
    enable_keying: bool = False
    keying_method: str | None = None
    keying_value: str = ""


class C2StackStageRequest(C2StackRequest):
    path: str | None = None
    content_b64: str | None = None
    filename: str | None = None


class C2StackProbeRequest(C2StackRequest):
    url_path: str = "/"
    headers: dict[str, str] = Field(default_factory=dict)
    method: str = "GET"


class C2StackTaskRequest(C2StackRequest):
    backend: str
    session_id: str
    command: str
    wait: int = 25
    callback_id: int | None = None


def c2_stack_status(req: C2StackRequest) -> dict[str, Any]:
    from redstrike.c2.stack import C2StackClient

    return C2StackClient(endpoint=req.endpoint).status()


def c2_stack_sessions(req: C2StackSessionsRequest) -> dict[str, Any]:
    from redstrike.c2.stack import C2StackClient

    return C2StackClient(endpoint=req.endpoint).sessions(backend=req.backend)


def c2_stack_capabilities(req: C2StackRequest) -> dict[str, Any]:
    from redstrike.c2.stack import C2StackClient

    return C2StackClient(endpoint=req.endpoint).capabilities()


def c2_stack_catalogues(req: C2StackSessionsRequest) -> dict[str, Any]:
    from redstrike.c2.stack import C2StackClient

    return C2StackClient(endpoint=req.endpoint).catalogues(backend=req.backend)


def c2_stack_build(req: C2StackBuildRequest) -> dict[str, Any]:
    import base64
    from pathlib import Path

    from redstrike.c2.stack import C2StackClient

    client = C2StackClient(endpoint=req.endpoint)
    if req.backend == "sliver":
        data = client.build_sliver(
            kind=req.kind, c2_url=req.c2_url, target_os=req.target_os, arch=req.arch
        )
        if data.get("ok") and req.retrieve and data.get("container_path"):
            dest = Path(req.out or f"sliver-{req.kind}-{req.arch}.exe")
            data = dict(data)
            data["retrieved"] = client.retrieve_container_file(str(data["container_path"]), dest)
        return data
    if req.backend == "havoc":
        data = client.build_havoc(
            arch=req.arch if req.arch in ("x64", "x86") else "x64",
            format=req.format or "Windows Exe",
            listener=req.listener,
            sleep=int(req.sleep) if req.sleep is not None else 5,
            jitter=req.jitter,
        )
    elif req.backend == "adaptix":
        data = client.build_adaptix(
            agent=req.agent,
            listener=req.listener or "cadre_http",
            arch=req.arch if req.arch in ("x64", "x86") else "x64",
            format=req.format or "Exe",
            sleep=str(req.sleep) if req.sleep is not None else "30s",
            ensure_listener=req.ensure_listener,
        )
    elif req.backend == "mythic":
        return client.build_mythic(
            output_type=req.output_type,
            filename=req.filename or "apollo-portal.exe",
            enable_keying=req.enable_keying,
            keying_method=req.keying_method or "Hostname",
            keying_value=req.keying_value,
        )
    else:
        return {"ok": False, "error": f"unsupported build backend '{req.backend}'"}

    # havoc/adaptix return raw bytes: base64 them for JSON and honor `out`.
    payload = data.pop("payload", None) if isinstance(data, dict) else None
    if payload is not None:
        if req.out:
            Path(req.out).write_bytes(payload)
            data["path"] = req.out
        data["size"] = len(payload)
        data["payload_b64"] = base64.b64encode(payload).decode("ascii")
    return data


def c2_stack_stage(req: C2StackStageRequest) -> dict[str, Any]:
    import base64

    from redstrike.c2.stack import C2StackClient

    client = C2StackClient(endpoint=req.endpoint)
    if req.path:
        return client.stage_file(req.path)
    if req.content_b64:
        try:
            content = base64.b64decode(req.content_b64)
        except (ValueError, TypeError) as exc:
            return {"ok": False, "error": f"content_b64 decode failed: {exc}"}
        return client.stage_bytes(content, req.filename or "upload.bin")
    return {"ok": False, "error": "provide either path or content_b64"}


def c2_stack_probe(req: C2StackProbeRequest) -> dict[str, Any]:
    from redstrike.c2.stack import C2StackClient

    return C2StackClient(endpoint=req.endpoint).probe_redirector(
        url_path=req.url_path, headers=req.headers, method=req.method
    )


def c2_stack_task(req: C2StackTaskRequest) -> dict[str, Any]:
    from redstrike.c2.stack import C2StackClient

    return C2StackClient(endpoint=req.endpoint).task(
        backend=req.backend,
        session_id=req.session_id,
        command=req.command,
        wait=req.wait,
        callback_id=req.callback_id,
    )
