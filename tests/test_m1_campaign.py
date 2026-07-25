from __future__ import annotations

import json
from pathlib import Path

import pytest

from cadre_strike.core.policy import POLICY_PROFILES
from cadre_strike.runtime.beachhead import Beachhead, BeachheadRouter, ExecutionPath
from cadre_strike.runtime.graph import load_campaign_graph
from cadre_strike.runtime.ledger import CredentialLedger, MissingCredentialError
from cadre_strike.runtime.orchestrator import CampaignOrchestrator

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
# Prefer CADRE M3 graph + lab seed (integration glue); demo graph has only stubs.
CADRE_GRAPH = (
    Path(__file__).resolve().parents[2]
    / "CADRE"
    / "attack-matrix"
    / "Campaign"
    / "automation"
    / "campaign-graph.yaml"
)
CADRE_SEED = (
    Path(__file__).resolve().parents[2]
    / "CADRE"
    / "attack-matrix"
    / "Campaign"
    / "automation"
    / "lab-seed-creds.json"
)
GRAPH = CADRE_GRAPH if CADRE_GRAPH.is_file() else EXAMPLES / "campaign-graph.m1.yaml"
SEED = CADRE_SEED if CADRE_SEED.is_file() else EXAMPLES / "seed.example.json"


@pytest.fixture
def automation_root(tmp_path: Path) -> Path:
    root = tmp_path / "linux"
    (root / "campaign-a").mkdir(parents=True)
    for name in (
        "T003-asrep-ws01.sh",
        "T002-kerb-ws01.sh",
        "T041-xpcmd-ws01.sh",
        "T043-impersonate-ws01.sh",
    ):
        (root / "campaign-a" / name).write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
    return root


def test_cadre_campaign_profile_registered() -> None:
    assert "cadre-campaign" in POLICY_PROFILES


def test_windows_beachhead_uses_ws01_exec(automation_root: Path, tmp_path: Path) -> None:
    orch = CampaignOrchestrator(
        engagement_id="lab-win",
        beachhead=Beachhead.WINDOWS,
        automation_root=automation_root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
    )
    orch.ledger.seed(json.loads(SEED.read_text(encoding="utf-8")))
    results = orch.run("1-3", dry_run=True)
    summary = orch.summary(results)

    assert summary["mbr01_count"] == 0
    assert all(r.plan.uses_ws01_exec for r in results if not r.skipped)
    assert all(r.plan.path is ExecutionPath.WS01 for r in results if not r.skipped)
    # M4: typed intents still egress via ws01 path; scripts use ws01-exec mechanism
    assert summary["ws01_exec_count"] + summary.get("intent_count", 0) >= 4
    assert all(
        r.plan.mechanism == "ws01-exec" or r.plan.mechanism.startswith("intent:")
        for r in results
        if not r.skipped
    )


def test_linux_beachhead_no_ws01_exec(automation_root: Path, tmp_path: Path) -> None:
    orch = CampaignOrchestrator(
        engagement_id="lab-lin",
        beachhead=Beachhead.LINUX,
        automation_root=automation_root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
    )
    orch.ledger.seed(json.loads(SEED.read_text(encoding="utf-8")))
    results = orch.run("1-3", dry_run=True)
    summary = orch.summary(results)

    assert summary["ws01_exec_count"] == 0
    assert summary["mbr01_count"] == 0
    assert all(not r.plan.uses_ws01_exec for r in results if not r.skipped)
    assert all(r.plan.path is ExecutionPath.LINUX60 for r in results if not r.skipped)
    assert all("ws01-exec" not in " ".join(r.plan.argv) for r in results)
    # linux beachhead: script steps → direct-linux60; intents → intent:* (still no ws01-exec)
    assert summary["linux_direct_count"] + summary.get("intent_count", 0) >= 4


def test_mbr01_blocked_without_flag(automation_root: Path) -> None:
    router = BeachheadRouter(automation_root=automation_root, allow_mbr01_stage=False)
    with pytest.raises(PermissionError, match="stage_mbr01"):
        router.effective_path(declared_path="stage_mbr01", beachhead=Beachhead.WINDOWS)


def test_mbr01_allowed_with_flag(automation_root: Path) -> None:
    router = BeachheadRouter(automation_root=automation_root, allow_mbr01_stage=True)
    plan = router.plan_step(
        node_id="X",
        title="exception",
        phase=5,
        declared_path="stage_mbr01",
        beachhead=Beachhead.WINDOWS,
        script="campaign-a/T003-asrep-ws01.sh",
        exception_reason="ws01 blocked by defense",
    )
    assert plan.path is ExecutionPath.STAGE_MBR01
    assert plan.uses_ws01_exec is False
    assert plan.exception_reason is not None


def test_ledger_fail_closed(tmp_path: Path) -> None:
    ledger = CredentialLedger("empty", root=tmp_path)
    with pytest.raises(MissingCredentialError):
        ledger.require("intern_blue")


def test_ledger_seed_and_require(tmp_path: Path) -> None:
    ledger = CredentialLedger("seeded", root=tmp_path)
    ledger.seed(json.loads(SEED.read_text(encoding="utf-8")))
    cred = ledger.require("analyst_t1")
    assert cred.username == "analyst_t1"
    assert cred.password is not None


def test_missing_requires_cred_skips_step(automation_root: Path, tmp_path: Path) -> None:
    orch = CampaignOrchestrator(
        engagement_id="no-seed",
        beachhead=Beachhead.WINDOWS,
        automation_root=automation_root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
        branches="spine",
    )
    # No seed — T003 ok (null requires), T002 needs intern_blue
    results = orch.run("1-2", dry_run=True)
    by_id = {r.plan.node_id: r for r in results}
    assert "T003" in by_id
    assert by_id["T003"].skipped is False
    assert by_id["T002"].skipped is True
    assert "intern_blue" in (by_id["T002"].skip_reason or "")


def test_load_graph_has_phase_1_3_spine_nodes() -> None:
    graph = load_campaign_graph(GRAPH)
    spine_p13 = {n.id for n in graph.nodes if n.branch == "spine" and n.phase in {1, 2, 3}}
    assert {"T003", "T002", "T041", "T043"} <= spine_p13


def test_cli_dry_run_windows(automation_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cadre_strike.cli import campaign as campaign_cli

    monkeypatch.setenv("REDSTRIKE_HOME", str(tmp_path / "redstrike"))
    code = campaign_cli.main(
        [
            "run",
            "--phase",
            "1-3",
            "--beachhead",
            "windows",
            "--engage",
            "cli-lab",
            "--graph",
            str(GRAPH),
            "--automation-root",
            str(automation_root),
            "--seed",
            str(SEED),
            "--json",
        ]
    )
    assert code == 0
