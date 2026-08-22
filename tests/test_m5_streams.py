from __future__ import annotations

from pathlib import Path

import pytest

from redstrike.cli.campaign import main as cli_main
from redstrike.runtime.graph import parse_branches
from redstrike.runtime.session import CampaignSession
from redstrike.runtime.streams import resolve_stream, stream_help

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
DEFAULT_GRAPH = EXAMPLES / "campaign-graph.m1.yaml"
SEED = EXAMPLES / "seed.example.json"


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


def test_cli_stream_e_standalone(
    automation_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REDSTRIKE_HOME", str(tmp_path / "home"))
    rc = cli_main(
        [
            "stream",
            "E",
            "--engage",
            "cli-e",
            "--graph",
            str(DEFAULT_GRAPH),
            "--automation-root",
            str(automation_root),
            "--seed",
            str(SEED),
            "--no-preflight",
            "--json",
        ]
    )
    assert rc == 0
