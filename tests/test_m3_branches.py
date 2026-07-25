from __future__ import annotations

from pathlib import Path

import pytest

from cadre_strike.runtime.graph import load_campaign_graph, parse_branches
from cadre_strike.runtime.preflight import preflight
from cadre_strike.runtime.session import CampaignSession, default_seed_path

CADRE_AUTO = (
    Path(__file__).resolve().parents[2]
    / "CADRE"
    / "attack-matrix"
    / "Campaign"
    / "automation"
)
GRAPH = CADRE_AUTO / "campaign-graph.yaml"
SEED = CADRE_AUTO / "lab-seed-creds.json"
PROFILES = CADRE_AUTO / "lab-profiles.yaml"


@pytest.fixture
def automation_root(tmp_path: Path) -> Path:
    root = tmp_path / "linux"
    scripts = [
        "campaign-a/T003-asrep-ws01.sh",
        "attacks/WT015-acl-forcechangepassword.sh",
        "attacks/WT050-esc1.sh",
        "attacks/WT034-sccm-naa-extraction.sh",
        "attacks/WT040-mssql-linked-server-hop.sh",
        "attacks/WT031-password-spray.sh",
    ]
    for rel in scripts:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
    return root


@pytest.mark.skipif(not GRAPH.is_file(), reason="CADRE graph missing")
def test_m3_graph_has_all_branches() -> None:
    graph = load_campaign_graph(GRAPH)
    branches = {n.branch for n in graph.nodes}
    assert {"spine", "A", "B", "C", "D", "E", "F", "G", "sql-ai"} <= branches
    assert any(n.id == "T-UNPAC" and n.stub for n in graph.nodes)
    assert any(n.id == "T039" and n.hitl_gate == "site_takeover" for n in graph.nodes)


def test_parse_branches_defaults_and_all() -> None:
    assert parse_branches(None) == {"spine"}
    assert parse_branches("A,b") == {"A", "B"}
    assert "sql-ai" in parse_branches("all")
    with pytest.raises(ValueError):
        parse_branches("Z")


@pytest.mark.skipif(not GRAPH.is_file(), reason="CADRE graph missing")
def test_branch_filter_excludes_spine_when_only_a(automation_root: Path, tmp_path: Path) -> None:
    session = CampaignSession(
        "br-a",
        beachhead="windows",
        automation_root=automation_root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
        seed_path=SEED if SEED.is_file() else None,
        branches="A",
    )
    summary = session.run_phase("4-5", dry_run=True, include_preflight=False)
    ids = {s["node_id"] for s in summary["steps"]}
    assert "T015" in ids
    assert "T003" not in ids
    assert summary["branches"] == ["A"]


@pytest.mark.skipif(not GRAPH.is_file(), reason="CADRE graph missing")
def test_branch_c_preflight_warns_for_forest(automation_root: Path, tmp_path: Path) -> None:
    session = CampaignSession(
        "br-c",
        beachhead="windows",
        automation_root=automation_root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
        seed_path=SEED if SEED.is_file() else None,
        branches="C",
    )
    summary = session.run_phase("8", dry_run=True)
    assert summary["preflight"]["profile"] == "P-FOREST"
    assert "mbr02" in summary["preflight"]["required_hosts"]


@pytest.mark.skipif(not PROFILES.is_file(), reason="lab-profiles missing")
def test_preflight_loads_cadre_profiles() -> None:
    result = preflight({"D"}, profiles_path=PROFILES)
    assert result.profile == "P-LINUX"
    assert "linux01" in result.required_hosts


def test_default_seed_prefers_cadre_not_example() -> None:
    path = default_seed_path()
    assert path is not None
    # When CADRE sibling exists, must not be the placeholder example
    if SEED.is_file():
        assert path.resolve() == SEED.resolve()
        assert "CHANGE_ME" not in path.read_text(encoding="utf-8")
