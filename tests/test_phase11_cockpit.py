"""Tests for check --graph, tool provenance, replay harness, cockpit endpoints."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from test_core_hardening import ScriptedRunner, _base_outputs, _ok, _orchestrator

from redstrike.api import server
from redstrike.core.policy import ScopePolicy
from redstrike.runtime.intent_tools import tools_for_intent
from redstrike.runtime.orchestrator import CampaignOrchestrator
from redstrike.runtime.session import CampaignSession


@pytest.fixture
def automation_root(tmp_path: Path) -> Path:
    root = tmp_path / "linux"
    for rel in ("s/base.sh", "s/dep.sh", "s/cond.sh", "s/td.sh"):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    return root


@pytest.fixture
def fixture_graph(tmp_path: Path) -> Path:
    from test_core_hardening import GRAPH_YAML

    graph = tmp_path / "hardening.yaml"
    graph.write_text(GRAPH_YAML, encoding="utf-8")
    return graph


# ---------------------------------------------------------------------------
# intent -> tool mapping (5)
# ---------------------------------------------------------------------------

def test_tools_for_intent_mapping() -> None:
    assert tools_for_intent("certipy.req") == ["certipy"]
    assert tools_for_intent("impacket.secretsdump") == ["impacket"]
    assert tools_for_intent("sql.mssqlclient") == ["impacket"]  # family fallback
    assert tools_for_intent("entra.kerberos_ticket") == ["aadinternals"]
    assert tools_for_intent("c2.havoc.shell") == []  # C2 delivery owns it
    assert tools_for_intent("winrs.command") == []  # Windows-native
    assert tools_for_intent("adcs.pyesc17") == []  # operator shim
    assert tools_for_intent(None) == []
    assert tools_for_intent("totally.unknown") == []


def test_every_registered_intent_resolves() -> None:
    from redstrike.runtime.intents import DEFAULT_REGISTRY

    for intent in DEFAULT_REGISTRY.known():
        tools_for_intent(intent)  # must not raise; unknown families -> []


# ---------------------------------------------------------------------------
# check --graph readiness (5)
# ---------------------------------------------------------------------------

def test_graph_readiness_reports_missing_linux_tool(tmp_path: Path, monkeypatch) -> None:
    from redstrike.cli.check import graph_readiness

    monkeypatch.delenv("REDSTRIKE_LINUX_CONTAINER", raising=False)
    monkeypatch.delenv("REDSTRIKE_LINUX_SSH", raising=False)
    monkeypatch.delenv("REDSTRIKE_WINDOWS_HOST", raising=False)
    graph = tmp_path / "g.yaml"
    graph.write_text(
        "version: 1\nname: ready-g\nnodes:\n"
        "  - id: R1\n    phase: 1\n    title: recon\n    path: linux\n"
        "    beachheads: [linux]\n    intent: certipy.find\n",
        encoding="utf-8",
    )
    report = graph_readiness(
        Path(graph), container=None, ssh_base=None, ssh_reachable=True,
        remote_tools_dir=None,
    )
    assert report["ready"] is False
    tool = next(t for t in report["tools"] if t["tool"] == "certipy")
    assert tool["nodes"] == ["R1"]
    assert tool["found"] is False


def test_graph_readiness_skips_stub_nodes(tmp_path: Path) -> None:
    from redstrike.cli.check import graph_readiness

    graph = tmp_path / "g.yaml"
    graph.write_text(
        "version: 1\nname: g\nnodes:\n"
        "  - id: S1\n    phase: 1\n    title: stub\n    path: direct\n    stub: true\n"
        "    intent: certipy.find\n",
        encoding="utf-8",
    )
    report = graph_readiness(
        Path(graph), container=None, ssh_base=None, ssh_reachable=True,
        remote_tools_dir=None,
    )
    assert report["ready"] is True  # stub nodes have no tool requirement
    assert report["tools"] == []


def test_check_graph_exit_code_missing(tmp_path: Path, monkeypatch, capsys) -> None:
    """`check --graph` exits 2 when a required tool is missing (readiness gate)."""
    from redstrike.cli.check import run_check

    monkeypatch.delenv("REDSTRIKE_LINUX_CONTAINER", raising=False)
    monkeypatch.delenv("REDSTRIKE_LINUX_SSH", raising=False)
    monkeypatch.delenv("REDSTRIKE_WINDOWS_HOST", raising=False)
    graph = tmp_path / "g.yaml"
    graph.write_text(
        "version: 1\nname: gate-g\nnodes:\n"
        "  - id: R1\n    phase: 1\n    title: recon\n    path: linux\n"
        "    beachheads: [linux]\n    intent: certipy.find\n",
        encoding="utf-8",
    )
    rc = run_check(
        scope="examples/scope.example.yaml", execute_ready=False,
        graph=str(graph), as_json=True,
    )
    assert rc == 2
    capsys.readouterr()  # drain JSON payload


# ---------------------------------------------------------------------------
# tool provenance in the journal (6)
# ---------------------------------------------------------------------------

def test_journal_records_tool_and_version(tmp_path: Path, fixture_graph: Path) -> None:
    """Intent nodes record tool + version on the StepResult and journal."""
    from redstrike.runtime.beachhead import Beachhead

    class _St:
        found = True
        version = "5.1.0"
        status = "ok"
        detail = ""
        is_compatible = True

    # pick a node that maps to certipy via the hardening fixture: use SCOPED
    # (certipy.find with 10.0.0.5 target + scope policy from the fixture tests)
    runner = ScriptedRunner({"certipy": _ok(["certipy"], "SCOPED_OK\n")})
    orch = CampaignOrchestrator(
        engagement_id="prov-eng-v",
        beachhead=Beachhead.LINUX,
        automation_root=tmp_path / "linux",
        graph_path=fixture_graph,
        ledger_root=tmp_path / "ledgers",
        runner=runner,
        node_ids="SCOPED",
        scope_policy=ScopePolicy(allowed_targets=["10.0.0.0/24"], allowed_domains=["corp.local"]),
    )
    with patch("redstrike.runtime.orchestrator.probe_tool_version", return_value=_St()):
        results = orch.run("4", dry_run=False, stop_on_hitl=False)
    assert results[0].tool == "certipy"
    assert results[0].tool_version == "5.1.0"
    journal = orch.activity.path.read_text(encoding="utf-8")
    assert '"tool_version":"5.1.0"' in journal

    # a non-intent node has no tool claim
    orch2 = CampaignOrchestrator(
        engagement_id="prov-eng-v2",
        beachhead=Beachhead.LINUX,
        automation_root=tmp_path / "linux",
        graph_path=fixture_graph,
        ledger_root=tmp_path / "ledgers",
        runner=ScriptedRunner({"td.sh": _ok(["s/td.sh"], "TD_OK\n")}),
        node_ids="TD",
    )
    r2 = orch2.run("5", dry_run=False, stop_on_hitl=False)
    assert r2[0].tool is None


def test_replay_record_then_replay_roundtrip(
    tmp_path: Path, automation_root: Path, fixture_graph: Path
) -> None:
    """Record a live run, replay it: same verification outcomes, no execution."""
    orch, _ = _orchestrator(
        tmp_path, automation_root, fixture_graph, _base_outputs(), node_ids="BASE,DEP"
    )
    first = orch.run("1-5", dry_run=False, stop_on_hitl=False, record_replay=True)
    assert any(r.verified for r in first)
    replay_dir = orch.store.dir / "replay"
    assert (replay_dir / "BASE.json").is_file()

    orch2, runner2 = _orchestrator(
        tmp_path, automation_root, fixture_graph, _base_outputs(), node_ids="BASE,DEP"
    )
    replayed = orch2.run("1-5", dry_run=False, stop_on_hitl=False, replay_mode=True)
    by_id = {r.plan.node_id: r for r in replayed}
    assert by_id["BASE"].verified is True
    assert by_id["DEP"].verified is True
    assert runner2.calls == []  # nothing executed on replay
    # recorded stdout matches the original run (deterministic replay)
    assert by_id["BASE"].stdout == first[0].stdout


def test_replay_drift_detected(
    tmp_path: Path, automation_root: Path, fixture_graph: Path
) -> None:
    """If the graph's command changed since recording, replay fails with drift."""
    orch, _ = _orchestrator(
        tmp_path, automation_root, fixture_graph, _base_outputs(), node_ids="BASE"
    )
    orch.run("1", dry_run=False, stop_on_hitl=False, record_replay=True)

    # Tamper: same node, different recorded argv (simulate by editing the file)
    rec_path = orch.store.dir / "replay" / "BASE.json"
    rec = json.loads(rec_path.read_text(encoding="utf-8"))
    rec["argv_sha256"] = "0" * 64
    rec_path.write_text(json.dumps(rec), encoding="utf-8")

    orch2, runner2 = _orchestrator(
        tmp_path, automation_root, fixture_graph, _base_outputs(), node_ids="BASE"
    )
    replayed = orch2.run("1", dry_run=False, stop_on_hitl=False, replay_mode=True)
    assert replayed[0].verified is False
    assert "replay drift" in (replayed[0].stderr or replayed[0].error or "")
    assert runner2.calls == []  # drift fails before any execution


def test_replay_cli_no_recordings(tmp_path: Path, capsys) -> None:
    from redstrike.cli.replay import main as replay_main

    graph = tmp_path / "g.yaml"
    graph.write_text(
        "version: 1\nname: g\nnodes:\n"
        "  - id: A\n    phase: 1\n    title: a\n    path: direct\n    stub: true\n",
        encoding="utf-8",
    )
    CampaignSession("empty-replay", ledger_root=tmp_path / "ledgers")
    rc = replay_main([
        "--engage", "empty-replay", "--graph", str(graph),
        "--ledger-root", str(tmp_path / "ledgers"),
    ])
    assert rc == 2
    capsys.readouterr()  # drain captured usage hint


# ---------------------------------------------------------------------------
# cockpit endpoints (Phase 11)
# ---------------------------------------------------------------------------

def test_api_campaign_graph_endpoint(tmp_path: Path, monkeypatch) -> None:
    from test_api import _OkService

    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    client = TestClient(server.create_app())
    graph = tmp_path / "ui-g.yaml"
    graph.write_text(
        "version: 1\nname: ui-graph\nnodes:\n"
        "  - id: A\n    phase: 1\n    title: a\n    path: direct\n    stub: true\n"
        "  - id: B\n    phase: 2\n    title: b\n    path: direct\n    stub: true\n"
        "    depends_on: [A]\n",
        encoding="utf-8",
    )
    resp = client.post("/campaign/graph", json={"graph": str(graph)})
    assert resp.status_code == 200
    body = resp.json()
    assert body["graph_name"] == "ui-graph"
    assert [n["id"] for n in body["nodes"]] == ["A", "B"]
    assert body["edges"] == [{"source": "A", "target": "B"}]
    assert body["nodes"][0]["status"] == "stub"
    # inspector fields (11.2)
    node_a = body["nodes"][0]
    assert node_a["beachheads"] == ["windows", "linux"]  # loader default
    assert node_a["intent"] is None
    assert node_a["intent_args"] is None
    assert node_a["success_marker"] is None
    assert node_a["depends_on"] == []
    assert node_a["teardown"] is None


def test_api_campaign_status_flattens_live_state(tmp_path: Path, monkeypatch) -> None:
    """The cockpit reads pending_gate/completed/attempted at top level."""
    from test_api import _OkService

    monkeypatch.setenv("REDSTRIKE_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    client = TestClient(server.create_app())

    start = client.post("/campaign/start", json={"engagement_id": "ui-flat"})
    assert start.status_code == 200
    resp = client.post("/campaign/status", json={"engagement_id": "ui-flat"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["pending_gate"] is None
    assert body["completed_nodes"] == {}
    assert body["attempted_nodes"] == {}


def test_api_credential_matrix_masked_and_reveal_audited(
    tmp_path: Path, monkeypatch
) -> None:
    from test_api import _OkService

    from redstrike.runtime.ledger import Credential, CredentialLedger

    monkeypatch.setenv("REDSTRIKE_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    client = TestClient(server.create_app())

    ledger = CredentialLedger("ui-creds", root=tmp_path / "home" / "engagements")
    ledger.put(Credential(name="seed", username="analyst", password="hunter2", nt_hash="a" * 32))

    resp = client.post("/campaign/status", json={"engagement_id": "ui-creds"})
    assert resp.status_code == 200
    creds = resp.json()["credentials"]
    entry = next(c for c in creds if c["name"] == "seed")
    assert entry["has_password"] is True
    assert "password" not in entry  # raw value never ships in status
    assert entry["password_mask"]

    reveal = client.post(
        "/campaign/credential/reveal", json={"engagement_id": "ui-creds", "name": "seed"}
    )
    assert reveal.status_code == 200
    assert reveal.json()["password"] == "hunter2"

    # audit trail records the reveal
    from redstrike.runtime.hitl import EngagementStore

    state = EngagementStore("ui-creds").load()  # default root honors REDSTRIKE_HOME
    assert state is not None and state.reveals and state.reveals[-1]["name"] == "seed"

    missing = client.post(
        "/campaign/credential/reveal", json={"engagement_id": "ui-creds", "name": "nope"}
    )
    assert missing.status_code == 404


def test_events_endpoint_streams_journal(tmp_path: Path, monkeypatch) -> None:
    from test_api import _OkService

    from redstrike.runtime.hitl import EngagementStore

    monkeypatch.setenv("REDSTRIKE_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    client = TestClient(server.create_app())

    # create the engagement, then append a known journal line
    start = client.post("/campaign/start", json={"engagement_id": "sse-eng"})
    assert start.status_code == 200
    journal = EngagementStore("sse-eng").dir / "activity-sse-eng.jsonl"
    with journal.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"ts": "T", "event": "test_event", "node_id": "X"}) + "\n")

    with client.stream("GET", "/campaign/events/sse-eng?follow_seconds=1") as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        body = "".join(chunk for chunk in resp.iter_text())
    assert "test_event" in body
    assert "event: end" in body


def test_ui_bundle_served(tmp_path: Path, monkeypatch) -> None:
    """The pre-built SPA is mounted at /ui/ when present."""
    from test_api import _OkService

    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    client = TestClient(server.create_app())
    resp = client.get("/ui/")
    assert resp.status_code == 200
    assert "RedStrike Cockpit" in resp.text
