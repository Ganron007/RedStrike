from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field  # noqa: F401 — Field used by IntentPreviewRequest

from redstrike.core.runner import redact_argv
from redstrike.runtime.hitl import KNOWN_GATES
from redstrike.runtime.intents import DEFAULT_REGISTRY
from redstrike.runtime.session import CampaignSession
from redstrike.runtime.streams import resolve_stream


class CampaignStartRequest(BaseModel):
    engagement_id: str
    beachhead: str = "windows"
    operator: str | None = None
    allow_mbr01_stage: bool = False
    graph: str | None = None
    automation_root: str | None = None
    cadre_root: str | None = None
    seed: str | None = None
    branches: str = "spine"


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
    dry_run: bool = True
    stop_on_hitl: bool = True
    allow_mbr01_stage: bool = False
    graph: str | None = None
    automation_root: str | None = None
    cadre_root: str | None = None
    seed: str | None = None
    branches: str = "spine"
    profile: str | None = None
    prefer_script: bool = False


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
    dry_run: bool = True
    graph: str | None = None
    automation_root: str | None = None
    cadre_root: str | None = None
    seed: str | None = None
    profile: str | None = None


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
        cadre_root=getattr(req, "cadre_root", None),
        allow_mbr01_stage=bool(getattr(req, "allow_mbr01_stage", False)),
        seed_path=getattr(req, "seed", None),
        branches=getattr(req, "branches", "spine") or "spine",
        prefer_script=bool(getattr(req, "prefer_script", False)),
    )


def intent_preview(req: IntentPreviewRequest) -> dict[str, Any]:
    argv = DEFAULT_REGISTRY.build(req.intent, req.args)
    return {
        "intent": req.intent,
        "argv": redact_argv(argv),
        "known_intents": DEFAULT_REGISTRY.known(),
    }


def campaign_start(req: CampaignStartRequest) -> dict[str, Any]:
    return _session(req).start()


def campaign_approve(req: CampaignApproveRequest) -> dict[str, Any]:
    if req.gate not in KNOWN_GATES:
        raise ValueError(f"unknown gate '{req.gate}'; known={sorted(KNOWN_GATES)}")
    return _session(req).approve(req.gate, note=req.note)


def campaign_run_phase(req: CampaignRunRequest) -> dict[str, Any]:
    return _session(req).run_phase(
        req.phase,
        dry_run=req.dry_run,
        stop_on_hitl=req.stop_on_hitl,
        profile=req.profile,
    )


def campaign_status(req: CampaignStatusRequest) -> dict[str, Any]:
    return _session(req).status()


def campaign_stream(req: CampaignStreamRequest) -> dict[str, Any]:
    spec = resolve_stream(req.stream)
    session = CampaignSession(
        req.engagement_id,
        beachhead=req.beachhead or spec["beachhead"],
        operator=req.operator,
        automation_root=req.automation_root,
        graph_path=req.graph,
        cadre_root=req.cadre_root,
        seed_path=req.seed,
        branches=spec["branch"],
    )
    data = session.run_phase(
        spec["phase"],
        dry_run=req.dry_run,
        stop_on_hitl=True,
        profile=req.profile,
    )
    data["stream"] = req.stream.upper()
    return data
