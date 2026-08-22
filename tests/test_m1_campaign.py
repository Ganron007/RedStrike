from __future__ import annotations

import json
from pathlib import Path

import pytest

from redstrike.core.policy import POLICY_PROFILES
from redstrike.runtime.beachhead import Beachhead, BeachheadRouter, ExecutionPath, OperatorMode
from redstrike.runtime.graph import load_campaign_graph, resolve_graph_path
from redstrike.runtime.ledger import CredentialLedger, MissingCredentialError
from redstrike.runtime.orchestrator import CampaignOrchestrator

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
GRAPH = EXAMPLES / "campaign-graph.m1.yaml"
SEED = EXAMPLES / "seed.example.json"
DEMO_SCRIPTS = (
    "campaign-a/demo-recon.sh",
    "campaign-a/demo-creds.sh",
    "campaign-a/demo-exec.sh",
    "campaign-a/demo-lateral.sh",
    "campaign-a/demo-gated.sh",
    "attacks/demo-acl.sh",
    "campaign-e/demo-e.sh",
    "campaign-f/demo-f.sh",
)


@pytest.fixture
def automation_root(tmp_path: Path) -> Path:
    root = tmp_path / "linux"
    for rel in DEMO_SCRIPTS:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
    return root


def test_campaign_and_standalone_profiles_registered() -> None:
    assert "gated" in POLICY_PROFILES
    assert "autonomous" in POLICY_PROFILES
    assert "standalone" in POLICY_PROFILES
    assert "campaign" in POLICY_PROFILES


def test_resolve_graph_uses_bundled_example() -> None:
    path = resolve_graph_path()
    assert path.resolve() == GRAPH.resolve()


def test_windows_beachhead_uses_ws01_exec(automation_root: Path, tmp_path: Path) -> None:
    orch = CampaignOrchestrator(
        engagement_id="lab-win",
        beachhead=Beachhead.WINDOWS,
        operator=OperatorMode.PROVISIONING,
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
    assert summary["ws01_exec_count"] + summary.get("intent_count", 0) >= 4
    assert all(
        r.plan.mechanism == "ws01-exec" or r.plan.mechanism.startswith("intent:")
        for r in results
        if not r.skipped
    )
    payload = next(r.to_dict() for r in results if not r.skipped)
    assert payload["started_at"] and payload["started_at"].endswith("Z")
    assert payload["finished_at"] and payload["finished_at"].endswith("Z")
    assert "T" in payload["started_at"]
    assert summary["started_at"]
    assert summary["finished_at"]
    assert payload["verified"] is False
    assert payload["verify_status"] == "dry_run"


def test_ws01_operator_uses_local_mechanism(automation_root: Path, tmp_path: Path) -> None:
    orch = CampaignOrchestrator(
        engagement_id="lab-native",
        beachhead=Beachhead.WINDOWS,
        operator=OperatorMode.WS01,
        automation_root=automation_root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
        prefer_script=True,
    )
    orch.ledger.seed(json.loads(SEED.read_text(encoding="utf-8")))
    results = orch.run("1-3", dry_run=True)
    summary = orch.summary(results)

    assert summary["operator"] == "ws01"
    assert summary["ws01_exec_count"] == 0
    assert summary["local_ws01_count"] >= 1
    assert all(not r.plan.uses_ws01_exec for r in results if not r.skipped)
    assert all(
        r.plan.mechanism == "local-ws01" for r in results if not r.skipped and r.plan.script
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
        script="campaign-a/demo-recon.sh",
        exception_reason="ws01 blocked by defense",
    )
    assert plan.path is ExecutionPath.STAGE_MBR01
    assert plan.uses_ws01_exec is False
    assert plan.exception_reason is not None


def test_ledger_fail_closed(tmp_path: Path) -> None:
    ledger = CredentialLedger("empty", root=tmp_path)
    with pytest.raises(MissingCredentialError):
        ledger.require("operator_user")


def test_ledger_seed_and_require(tmp_path: Path) -> None:
    ledger = CredentialLedger("seeded", root=tmp_path)
    ledger.seed(json.loads(SEED.read_text(encoding="utf-8")))
    cred = ledger.require("operator_user")
    assert cred.username == "operator_user"
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
    results = orch.run("1-2", dry_run=True)
    by_id = {r.plan.node_id: r for r in results}
    assert "DEMO-RECON" in by_id
    assert by_id["DEMO-RECON"].skipped is False
    assert by_id["DEMO-CREDS"].skipped is True
    assert "operator_user" in (by_id["DEMO-CREDS"].skip_reason or "")


def test_load_graph_has_phase_1_3_spine_nodes() -> None:
    graph = load_campaign_graph(GRAPH)
    spine_p13 = {n.id for n in graph.nodes if n.branch == "spine" and n.phase in {1, 2, 3}}
    assert {"DEMO-RECON", "DEMO-CREDS", "DEMO-EXEC", "DEMO-LATERAL"} <= spine_p13


def test_cli_dry_run_windows(automation_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from redstrike.cli import campaign as campaign_cli

    monkeypatch.setenv("REDSTRIKE_HOME", str(tmp_path / "redstrike"))
    code = campaign_cli.main(
        [
            "run",
            "--phase",
            "1-3",
            "--beachhead",
            "windows",
            "--operator",
            "provisioning",
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


def test_parse_node_ids_order_and_dedupe() -> None:
    from redstrike.runtime.graph import parse_node_ids

    assert parse_node_ids(None) is None
    assert parse_node_ids("") is None
    assert parse_node_ids(" T009, T013,T009 ;T014 ") == ("T009", "T013", "T014")


def test_select_nodes_by_id_ignores_phase_and_branch(automation_root: Path, tmp_path: Path) -> None:
    orch = CampaignOrchestrator(
        engagement_id="nodes-filter",
        beachhead=Beachhead.WINDOWS,
        operator=OperatorMode.PROVISIONING,
        automation_root=automation_root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
        branches="spine",
        node_ids="DEMO-ACL,DEMO-RECON",
    )
    orch.ledger.seed(json.loads(SEED.read_text(encoding="utf-8")))
    selected = orch.select_nodes("1-3")
    assert [n.id for n in selected] == ["DEMO-ACL", "DEMO-RECON"]


def test_select_nodes_unknown_id_fails_closed(automation_root: Path, tmp_path: Path) -> None:
    orch = CampaignOrchestrator(
        engagement_id="nodes-bad",
        beachhead=Beachhead.WINDOWS,
        automation_root=automation_root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
        node_ids="NO-SUCH",
    )
    with pytest.raises(ValueError, match="unknown node id"):
        orch.select_nodes("1-3")


def test_select_nodes_wrong_beachhead_fails_closed(automation_root: Path, tmp_path: Path) -> None:
    orch = CampaignOrchestrator(
        engagement_id="nodes-bh",
        beachhead=Beachhead.LINUX,
        automation_root=automation_root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
        node_ids="DEMO-ACL",
    )
    with pytest.raises(ValueError, match="not valid for beachhead linux"):
        orch.select_nodes("1-3")
