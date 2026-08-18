from __future__ import annotations

from pathlib import Path

import pytest

from redstrike.cli.campaign import main as cli_main
from redstrike.runtime.graph import STREAM_SPECS, load_campaign_graph, parse_branches
from redstrike.runtime.preflight import preflight
from redstrike.runtime.session import CampaignSession
from redstrike.runtime.streams import resolve_stream, stream_help

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
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
LINUX_AUTO = (
    Path(__file__).resolve().parents[2] / "CADRE" / "attack-matrix" / "04-automation" / "linux"
)


@pytest.fixture
def automation_root(tmp_path: Path) -> Path:
    root = tmp_path / "linux"
    for rel in [
        "campaign-e/wt069-dns-dga.sh",
        "campaign-e/wt070-dns-txt.sh",
        "campaign-f/F01-webhook-postinstall.sh",
        "campaign-f/F10-webhook-exfil-probe.sh",
        "campaign-e/demo-e.sh",
        "campaign-f/demo-f.sh",
    ]:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
    return root


def test_stream_specs() -> None:
    assert resolve_stream("e")["phase"] == "9"
    assert resolve_stream("F")["branch"] == "F"
    assert {s["stream"] for s in stream_help()} == {"E", "F"}
    with pytest.raises(ValueError):
        resolve_stream("Z")


def test_parse_branches_includes_e_f() -> None:
    assert parse_branches("E,F") == {"E", "F"}
    assert {"E", "F"} <= parse_branches("all")


def test_stream_e_f_dry_run_standalone(automation_root: Path, tmp_path: Path) -> None:
    demo = EXAMPLES / "campaign-graph.m1.yaml"
    seed = EXAMPLES / "seed.example.json"
    e_session = CampaignSession(
        "stream-e-demo",
        beachhead="linux",
        automation_root=automation_root,
        graph_path=demo,
        ledger_root=tmp_path / "ledgers",
        seed_path=seed,
        branches="E",
    )
    e_summary = e_session.run_phase("9", dry_run=True, include_preflight=False)
    assert "DEMO-E" in {s["node_id"] for s in e_summary["steps"]}
    assert "DEMO-RECON" not in {s["node_id"] for s in e_summary["steps"]}
    assert e_summary["ws01_exec_count"] == 0

    f_session = CampaignSession(
        "stream-f-demo",
        beachhead="linux",
        automation_root=automation_root,
        graph_path=demo,
        ledger_root=tmp_path / "ledgers-f",
        seed_path=seed,
        branches="F",
    )
    f_summary = f_session.run_phase("10", dry_run=True, include_preflight=False)
    assert "DEMO-F" in {s["node_id"] for s in f_summary["steps"]}
    assert f_summary["ws01_exec_count"] == 0


@pytest.mark.skipif(not GRAPH.is_file(), reason="CADRE graph missing")
def test_m5_graph_has_e_f_streams() -> None:
    graph = load_campaign_graph(GRAPH)
    assert graph.version >= 5
    branches = {n.branch for n in graph.nodes}
    assert {"E", "F"} <= branches
    e_nodes = [n for n in graph.nodes if n.branch == "E"]
    f_nodes = [n for n in graph.nodes if n.branch == "F"]
    assert len(e_nodes) >= 13
    assert len(f_nodes) == 10
    assert all(n.phase == 9.0 for n in e_nodes)
    assert all(n.phase == 10.0 for n in f_nodes)
    assert all(n.path == "external60_phase0" for n in e_nodes + f_nodes)


@pytest.mark.skipif(not GRAPH.is_file(), reason="CADRE graph missing")
def test_branch_e_dry_run(automation_root: Path, tmp_path: Path) -> None:
    session = CampaignSession(
        "stream-e",
        beachhead="linux",
        automation_root=automation_root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
        seed_path=SEED if SEED.is_file() else None,
        branches="E",
    )
    summary = session.run_phase("9", dry_run=True, include_preflight=False)
    ids = {s["node_id"] for s in summary["steps"]}
    assert "WT069" in ids
    assert "T003" not in ids
    assert summary["branches"] == ["E"]
    assert all(s["path"] == "external60_phase0" for s in summary["steps"] if not s.get("skipped"))


@pytest.mark.skipif(not GRAPH.is_file(), reason="CADRE graph missing")
def test_branch_f_dry_run(automation_root: Path, tmp_path: Path) -> None:
    session = CampaignSession(
        "stream-f",
        beachhead="linux",
        automation_root=automation_root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
        seed_path=SEED if SEED.is_file() else None,
        branches="F",
    )
    summary = session.run_phase("10", dry_run=True, include_preflight=False)
    ids = {s["node_id"] for s in summary["steps"]}
    assert "F01" in ids and "F10" in ids
    assert summary["ws01_exec_count"] == 0


@pytest.mark.skipif(not PROFILES.is_file(), reason="lab-profiles missing")
def test_preflight_e_f_profiles() -> None:
    e = preflight({"E"}, profiles_path=PROFILES)
    assert e.profile == "P-NETDEF"
    assert "monitor" in e.required_hosts
    f = preflight({"F"}, profiles_path=PROFILES)
    assert f.profile == "P-SUPPLY"
    assert "linux01" in f.required_hosts


def test_cli_stream_e_standalone(
    automation_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REDSTRIKE_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("CADRE_ROOT", raising=False)
    rc = cli_main(
        [
            "stream",
            "E",
            "--engage",
            "cli-e",
            "--graph",
            str(EXAMPLES / "campaign-graph.m1.yaml"),
            "--automation-root",
            str(automation_root),
            "--seed",
            str(EXAMPLES / "seed.example.json"),
            "--no-preflight",
            "--json",
        ]
    )
    assert rc == 0


@pytest.mark.skipif(not LINUX_AUTO.is_dir(), reason="CADRE linux automation missing")
def test_wrapper_scripts_exist() -> None:
    assert (LINUX_AUTO / "campaign-e" / "wt069-dns-dga.sh").is_file()
    assert (LINUX_AUTO / "campaign-f" / "F01-webhook-postinstall.sh").is_file()
    assert (LINUX_AUTO / "campaign-f" / "F10-webhook-exfil-probe.sh").is_file()
    assert STREAM_SPECS["E"]["phase"] == "9"
