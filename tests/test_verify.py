"""In-engine verification — live 2026-08-22 DFIR false-ok snippets must not pass."""

from __future__ import annotations

import json
from pathlib import Path

from redstrike.core.models import CommandResult
from redstrike.runtime.beachhead import Beachhead, OperatorMode
from redstrike.runtime.graph import load_campaign_graph
from redstrike.runtime.orchestrator import CampaignOrchestrator
from redstrike.runtime.verify import default_success_marker, verify_step_output

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
FIXTURE_GRAPH = Path(__file__).resolve().parent / "fixtures" / "graph-verify.yaml"

# Simulated run logs for verification engine testing
LIVE_T013_FALSE_OK = """=== T013 WriteDacl | RUN-T013-WRITEDACL-20260822 | T0=2026-08-22T05:28:12Z ===
[localhost] Connecting to remote server localhost failed with the following error message : Access is denied.
=== T013 run complete ===
"""

LIVE_T004_BH_FALSE_OK = """=== T004-BH BloodHound collection | RUN-T004-BH-20260822 | T0=2026-08-22T05:29:01Z ===

MANUAL STEP REQUIRED (WinRM cannot bind to LDAP for SharpHound):
On ws01, run as child.example.lab\\analyst_t1 (RDP or runas):
T004_INFO: no zip found in C:\\Tools\\ADTools\\T004-bh-out — run the manual step first.
=== T004-BH run complete ===
"""

LIVE_T028_EXPECTED_BLOCK = """=== T028 | RUN-T028-NULL-20260822 | T0=2026-08-22T05:27:52Z ===
Cannot connect to server. Error was NT_STATUS_ACCESS_DENIED
T028_OK
"""

LIVE_T003_VERIFIED = """=== T003 AS-REP | CASE=RUN-T003-ASREP-20260822 | T0=2026-08-22T05:28:04Z ===
[*] Using /nopreauth with user: intern_blue
[+] Got TGT for intern_blue@CHILD.EXAMPLE.LAB
$krb5asrep$23$intern_blue@CHILD.EXAMPLE.LAB:aabbccddeeff
T003_OK
"""


def test_default_marker_normalizes_hyphens() -> None:
    assert default_success_marker("T013") == r"T013_OK"
    assert default_success_marker("H-ASSUME") == r"H_ASSUME_OK"
    assert default_success_marker("T004-MBR01-BH") == r"T004_MBR01_BH_OK"


def test_live_t013_access_denied_is_not_verified() -> None:
    outcome = verify_step_output(
        node_id="T013",
        return_code=0,
        stdout=LIVE_T013_FALSE_OK,
    )
    assert outcome.verified is False
    assert outcome.status == "unverified"
    assert "Access is denied" in outcome.reason or "fail pattern" in outcome.reason


def test_live_t004_manual_step_is_not_verified() -> None:
    outcome = verify_step_output(
        node_id="T004-BH",
        return_code=0,
        stdout=LIVE_T004_BH_FALSE_OK,
        success_marker=r"T004_BH_OK",
    )
    assert outcome.verified is False
    assert "MANUAL STEP" in outcome.reason


def test_t028_expected_deny_is_verified_when_marked() -> None:
    outcome = verify_step_output(
        node_id="T028",
        return_code=0,
        stdout=LIVE_T028_EXPECTED_BLOCK,
        expected_errors=("NT_STATUS_ACCESS_DENIED",),
    )
    assert outcome.verified is True
    assert outcome.status == "verified"


def test_t028_deny_without_marker_is_unverified() -> None:
    outcome = verify_step_output(
        node_id="T028",
        return_code=0,
        stdout="Cannot connect to server. Error was NT_STATUS_ACCESS_DENIED\n",
        expected_errors=("NT_STATUS_ACCESS_DENIED",),
    )
    assert outcome.verified is False
    assert "missing success marker" in outcome.reason


def test_t003_hash_plus_marker_is_verified() -> None:
    outcome = verify_step_output(node_id="T003", return_code=0, stdout=LIVE_T003_VERIFIED)
    assert outcome.verified is True


def test_nonzero_rc_is_not_verified_even_with_marker() -> None:
    outcome = verify_step_output(node_id="T013", return_code=1, stdout="T013_OK\n")
    assert outcome.verified is False
    assert "return_code=1" in outcome.reason


def test_dry_run_and_stub_are_not_verified() -> None:
    dry = verify_step_output(node_id="T013", dry_run=True, return_code=0, stdout="T013_OK")
    stub = verify_step_output(node_id="T100", stub=True, skipped=True)
    assert dry.verified is False and dry.status == "dry_run"
    assert stub.verified is False and stub.status == "stub"


class _ScriptedRunner:
    def __init__(self, outputs: dict[str, CommandResult]) -> None:
        self.outputs = outputs

    def run(self, argv: list[str]) -> CommandResult:
        blob = " ".join(argv)
        for key, result in self.outputs.items():
            if key in blob:
                return result
        return CommandResult(command=argv, return_code=1, stdout="", stderr="no fixture", duration_seconds=0.0)


def test_orchestrator_execute_rejects_live_false_ok(tmp_path: Path) -> None:
    graph = FIXTURE_GRAPH
    assert graph.is_file()
    runner = _ScriptedRunner(
        {
            "t013.sh": CommandResult(
                command=["t013.sh"],
                return_code=0,
                stdout=LIVE_T013_FALSE_OK,
                stderr="",
                duration_seconds=0.2,
            ),
            "t028.sh": CommandResult(
                command=["t028.sh"],
                return_code=0,
                stdout=LIVE_T028_EXPECTED_BLOCK,
                stderr="",
                duration_seconds=0.1,
            ),
        }
    )
    orch = CampaignOrchestrator(
        engagement_id="verify-live",
        beachhead=Beachhead.LINUX,
        operator=OperatorMode.PROVISIONING,
        automation_root=tmp_path / "linux",
        graph_path=graph,
        ledger_root=tmp_path / "ledgers",
        runner=runner,
        prefer_script=True,
        branches="all",
    )
    (tmp_path / "linux" / "campaign-a").mkdir(parents=True)
    (tmp_path / "linux" / "campaign-a" / "t013.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "linux" / "campaign-a" / "t028.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    results = orch.run("0-4", dry_run=False, stop_on_hitl=False)
    by_id = {r.plan.node_id: r for r in results}
    assert by_id["T013"].verified is False
    assert by_id["T013"].error
    assert by_id["T028"].verified is True
    summary = orch.summary(results)
    assert summary["verified_count"] == 1
    assert summary["unverified_count"] == 1


def test_cli_execute_exits_1_on_unverified(tmp_path: Path, monkeypatch) -> None:
    from redstrike.cli import campaign as campaign_cli
    from redstrike.runtime import session as session_mod

    data = {
        "engagement_id": "x",
        "beachhead": "linux",
        "graph": "g",
        "branches": ["spine"],
        "steps": [
            {
                "node_id": "T013",
                "phase": 4,
                "branch": "A",
                "path": "ws01",
                "mechanism": "ws01-exec",
                "dry_run": False,
                "skipped": False,
                "verified": False,
                "verify_reason": "fail pattern matched",
                "return_code": 0,
            }
        ],
    }

    class _Fake:
        def run_phase(self, *args, **kwargs):
            return data

    monkeypatch.setattr(campaign_cli, "_session_from_args", lambda args: _Fake())
    monkeypatch.setattr(session_mod, "CampaignSession", lambda *a, **k: _Fake())
    code = campaign_cli.main(
        [
            "run",
            "--phase",
            "4",
            "--beachhead",
            "linux",
            "--engage",
            "cli-verify",
            "--execute",
            "--no-preflight",
            "--graph",
            str(EXAMPLES / "campaign-graph.m1.yaml"),
            "--automation-root",
            str(tmp_path),
        ]
    )
    assert code == 1


def test_graph_parses_verify_fields() -> None:
    graph = load_campaign_graph(FIXTURE_GRAPH)
    t028 = next(n for n in graph.nodes if n.id == "T028")
    t013 = next(n for n in graph.nodes if n.id == "T013")
    assert t028.expected_errors == ("NT_STATUS_ACCESS_DENIED",)
    assert t028.success_marker == "T028_OK"
    assert t013.success_marker is None
    assert json.dumps(t028.expected_errors)
