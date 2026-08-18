from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from redstrike.api.server import create_app
from redstrike.mcp import server as mcp_server
from redstrike.runtime.beachhead import Beachhead
from redstrike.runtime.graph import load_campaign_graph, parse_phase_filter
from redstrike.runtime.hitl import HitlGate
from redstrike.runtime.orchestrator import CampaignOrchestrator
from redstrike.runtime.session import CampaignSession

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
CADRE_AUTO = (
    Path(__file__).resolve().parents[2]
    / "CADRE"
    / "attack-matrix"
    / "Campaign"
    / "automation"
)
CADRE_GRAPH = CADRE_AUTO / "campaign-graph.yaml"
SEED = CADRE_AUTO / "lab-seed-creds.json"
if not SEED.is_file():
    SEED = EXAMPLES / "seed.example.json"


@pytest.fixture
def automation_root(tmp_path: Path) -> Path:
    root = tmp_path / "linux"
    for rel in (
        "campaign-a/T003-asrep-ws01.sh",
        "campaign-a/T002-kerb-ws01.sh",
        "campaign-a/T041-xpcmd-ws01.sh",
        "campaign-a/T043-impersonate-ws01.sh",
        "campaign-a/T009-dcsync-ws01.sh",
        "campaign-a/T010-golden-ws01.sh",
        "campaign-a/T011-silver-ws01.sh",
        "campaign-a/T012-diamond-ws01.sh",
        "campaign-a/T033-xforest-ws01.sh",
        "campaign-a/T042-clr-ws01.sh",
        "campaign-a/T028-nullsession.sh",
        "attacks/WT017-printerbug-spoolsample.sh",
        "campaign-a/demo-recon.sh",
        "campaign-a/demo-creds.sh",
        "campaign-a/demo-exec.sh",
        "campaign-a/demo-lateral.sh",
        "campaign-a/demo-gated.sh",
    ):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
    return root


@pytest.mark.skipif(not CADRE_GRAPH.is_file(), reason="CADRE graph not beside RedStrike")
def test_m2_graph_covers_spine_phases() -> None:
    graph = load_campaign_graph(CADRE_GRAPH)
    phases = {n.phase for n in graph.nodes}
    assert 0.5 in phases
    assert 6 in phases and 7 in phases and 8 in phases
    gated = {n.id: n.hitl_gate for n in graph.nodes if n.hitl_gate}
    assert gated["T009"] == "dcsync"
    assert gated["T010"] == "ticket"
    assert gated["T033"] == "forest"


def test_parse_phase_filter_half_phases() -> None:
    match = parse_phase_filter("0.5-3")
    assert match(0.5) and match(1) and match(3)
    assert not match(0) and not match(4)


def test_hitl_blocks_until_approved_standalone(automation_root: Path, tmp_path: Path) -> None:
    demo = EXAMPLES / "campaign-graph.m1.yaml"
    seed = EXAMPLES / "seed.example.json"
    session = CampaignSession(
        "hitl-demo",
        beachhead="windows",
        automation_root=automation_root,
        graph_path=demo,
        ledger_root=tmp_path / "ledgers",
        seed_path=seed,
    )
    summary = session.run_phase("6", dry_run=True, include_preflight=False)
    by_id = {s["node_id"]: s for s in summary["steps"]}
    assert by_id["DEMO-HITL"]["awaiting_approval"] is True

    session.approve(HitlGate.DCSYNC.value)
    summary2 = session.run_phase("6", dry_run=True, include_preflight=False)
    by_id2 = {s["node_id"]: s for s in summary2["steps"]}
    assert by_id2["DEMO-HITL"]["awaiting_approval"] is False
    assert by_id2["DEMO-HITL"]["skipped"] is False


@pytest.mark.skipif(not CADRE_GRAPH.is_file(), reason="CADRE graph not beside RedStrike")
def test_hitl_blocks_dcsync_until_approved(automation_root: Path, tmp_path: Path) -> None:
    session = CampaignSession(
        "hitl-lab",
        beachhead="windows",
        automation_root=automation_root,
        graph_path=CADRE_GRAPH,
        ledger_root=tmp_path / "ledgers",
        seed_path=SEED,
    )
    summary = session.run_phase("6-7", dry_run=True)
    by_id = {s["node_id"]: s for s in summary["steps"]}
    assert by_id["T009"]["awaiting_approval"] is True
    assert by_id["T010"]["awaiting_approval"] is True

    session.approve(HitlGate.DCSYNC.value)
    session.approve(HitlGate.TICKET.value)
    # Seed krbtgt for T010 require
    orch = CampaignOrchestrator(
        engagement_id="hitl-lab",
        beachhead=Beachhead.WINDOWS,
        automation_root=automation_root,
        graph_path=CADRE_GRAPH,
        ledger_root=tmp_path / "ledgers",
    )
    from redstrike.runtime.ledger import Credential

    orch.ledger.put(Credential(name="krbtgt", username="krbtgt", source="test"))

    summary2 = session.run_phase("6-7", dry_run=True)
    by_id2 = {s["node_id"]: s for s in summary2["steps"]}
    assert by_id2["T009"]["awaiting_approval"] is False
    assert by_id2["T009"]["skipped"] is False
    assert by_id2["T010"]["awaiting_approval"] is False


@pytest.mark.skipif(not CADRE_GRAPH.is_file(), reason="CADRE graph not beside RedStrike")
def test_execute_stops_on_first_gate(automation_root: Path, tmp_path: Path) -> None:
    session = CampaignSession(
        "hitl-stop",
        beachhead="windows",
        automation_root=automation_root,
        graph_path=CADRE_GRAPH,
        ledger_root=tmp_path / "ledgers",
        seed_path=SEED,
    )
    summary = session.run_phase("6", dry_run=False, stop_on_hitl=True)
    assert summary["state"]["status"] == "paused"
    assert summary["state"]["pending_gate"] == "dcsync"
    assert len(summary["steps"]) == 1
    assert summary["steps"][0]["awaiting_approval"] is True


def test_mbr01_still_requires_flag(automation_root: Path) -> None:
    from redstrike.runtime.beachhead import BeachheadRouter

    router = BeachheadRouter(automation_root=automation_root, allow_mbr01_stage=False)
    with pytest.raises(PermissionError):
        router.effective_path(declared_path="stage_mbr01", beachhead=Beachhead.WINDOWS)


def test_api_campaign_routes(automation_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDSTRIKE_HOME", str(tmp_path / "rs"))
    client = TestClient(create_app(profile="campaign"))
    start = client.post(
        "/campaign/start",
        json={
            "engagement_id": "api-lab",
            "beachhead": "windows",
            "operator": "provisioning",
            "automation_root": str(automation_root),
            "graph": str(EXAMPLES / "campaign-graph.m1.yaml"),
            "seed": str(EXAMPLES / "seed.example.json"),
        },
    )
    assert start.status_code == 200
    assert start.json()["ok"] is True
    assert start.json()["operator"] == "provisioning"

    run = client.post(
        "/campaign/run_phase",
        json={
            "engagement_id": "api-lab",
            "beachhead": "windows",
            "operator": "provisioning",
            "phase": "1-3",
            "dry_run": True,
            "automation_root": str(automation_root),
            "graph": str(EXAMPLES / "campaign-graph.m1.yaml"),
            "seed": str(EXAMPLES / "seed.example.json"),
        },
    )
    assert run.status_code == 200
    assert run.json()["ws01_exec_count"] >= 1
    assert run.json()["operator"] == "provisioning"

    status = client.post("/campaign/status", json={"engagement_id": "api-lab"})
    assert status.status_code == 200
    assert status.json()["engagement_id"] == "api-lab"


def test_mcp_exposes_campaign_tools(monkeypatch) -> None:
    import sys
    from types import ModuleType

    class FakeMCP:
        def __init__(self, name: str) -> None:
            self.name = name
            self.tools = {}

        def tool(self):
            def decorator(func):
                self.tools[func.__name__] = func
                return func

            return decorator

    mcp_module = ModuleType("mcp")
    mcp_server_module = ModuleType("mcp.server")
    mcp_fastmcp_module = ModuleType("mcp.server.fastmcp")
    mcp_fastmcp_module.FastMCP = FakeMCP
    fastmcp_module = ModuleType("fastmcp")
    fastmcp_module.FastMCP = FakeMCP
    monkeypatch.setitem(sys.modules, "mcp", mcp_module)
    monkeypatch.setitem(sys.modules, "mcp.server", mcp_server_module)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", mcp_fastmcp_module)
    monkeypatch.setitem(sys.modules, "fastmcp", fastmcp_module)
    monkeypatch.setattr(
        mcp_server,
        "_post",
        lambda api_url, path, payload: {"path": path, "payload": payload},
    )

    mcp = mcp_server.create_mcp("http://127.0.0.1:8890")
    for name in (
        "campaign_start",
        "campaign_approve",
        "campaign_run_phase",
        "campaign_status",
        "build_intent",
    ):
        assert name in mcp.tools
    assert mcp.tools["campaign_approve"]("e1", "dcsync")["path"] == "/campaign/approve"
    assert mcp.tools["build_intent"]("certipy.find", {"target": "dc"})["path"] == "/builders/preview"
