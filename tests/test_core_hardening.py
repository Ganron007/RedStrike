"""Tests for the core-hardening workstream: ledger integrity, approvals audit,
scope enforcement, resume/stop controls, dependency gates, secret parsing,
output scrubbing, teardown persistence, reporting, and the smaller fixes."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from redstrike.core.models import ADRequest, CallKind, CallSpec, CommandResult, OperationResponse
from redstrike.core.policy import ScopePolicy, load_scope_policy
from redstrike.core.runner import CommandRunner, redact_argv
from redstrike.core.secrets import extract_secrets, raw_output_requested, scrub_output
from redstrike.runtime import crypto
from redstrike.runtime.beachhead import Beachhead, ExecutionPath, OperatorMode, StepPlan
from redstrike.runtime.graph import load_campaign_graph, parse_branches
from redstrike.runtime.hitl import EngagementStore
from redstrike.runtime.ledger import Credential, CredentialLedger
from redstrike.runtime.orchestrator import CampaignOrchestrator
from redstrike.runtime.session import CampaignSession
from redstrike.runtime.teardown import TeardownQueue, load_queue, save_queue
from redstrike.runtime.verify import verify_step_output
from redstrike.runtime.ws01_transport import argv_for_plan

KERBEROAST_OUTPUT = (
    "[*] Action: Kerberoasting\n"
    "[*] ServicePrincipalName   : MSSQLSvc/sql01.corp.local:1433\n"
    "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$"
    "1a2b3c4d5e6f7081920a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6"
    "0718293a4b5c6d7e8f90a1b2c3d4e5f607182930a\n"
    "BASE_OK\n"
)


class ScriptedRunner:
    """Minimal test double: match a key in the joined argv, return its result."""

    def __init__(self, outputs: dict[str, CommandResult]) -> None:
        self.outputs = outputs
        self.calls: list[list[str]] = []

    def run(self, argv, **kwargs) -> CommandResult:
        self.calls.append(list(argv))
        blob = " ".join(argv)
        for key, result in self.outputs.items():
            if key in blob:
                return result
        return CommandResult(
            command=list(argv), return_code=1, stdout="", stderr="no fixture", duration_seconds=0.0
        )


def _ok(argv: list[str], stdout: str) -> CommandResult:
    return CommandResult(
        command=list(argv), return_code=0, stdout=stdout, stderr="", duration_seconds=0.0
    )


GRAPH_YAML = """
version: 1
name: hardening-fixture
nodes:
  - id: BASE
    phase: 1
    path: linux60
    beachheads: [linux]
    title: base step
    script: s/base.sh
    produces_cred: krb_hash
  - id: DEP
    phase: 2
    path: linux60
    beachheads: [linux]
    title: depends on base
    script: s/dep.sh
    depends_on: [BASE]
  - id: COND
    phase: 3
    path: linux60
    beachheads: [linux]
    title: conditional on base
    script: s/cond.sh
    when:
      verified: [BASE]
  - id: SCOPED
    phase: 4
    path: linux60
    beachheads: [linux]
    title: scope-checked intent node
    intent: certipy.find
    intent_args:
      target: "10.0.0.5"
      domain: "corp.local"
    targets: ["10.0.0.5"]
  - id: TD
    phase: 5
    path: linux60
    beachheads: [linux]
    title: node with declared teardown
    script: s/td.sh
    timeout_seconds: 30
    teardown:
      description: "remove test artifact"
      command: ["rm", "-f", "/tmp/rs-test-artifact"]
  - id: NONIDEM
    phase: 6
    path: linux60
    beachheads: [linux]
    title: non-idempotent node
    script: s/nonidem.sh
    idempotent: false
"""


@pytest.fixture
def fixture_graph(tmp_path: Path) -> Path:
    graph = tmp_path / "hardening.yaml"
    graph.write_text(GRAPH_YAML, encoding="utf-8")
    return graph


@pytest.fixture
def automation_root(tmp_path: Path) -> Path:
    root = tmp_path / "linux"
    for rel in ("s/base.sh", "s/dep.sh", "s/cond.sh", "s/td.sh", "s/nonidem.sh"):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    return root


def _orchestrator(
    tmp_path: Path,
    automation_root: Path,
    fixture_graph: Path,
    outputs: dict[str, CommandResult],
    **kwargs,
) -> tuple[CampaignOrchestrator, ScriptedRunner]:
    runner = ScriptedRunner(outputs)
    orch = CampaignOrchestrator(
        engagement_id=kwargs.pop("engagement_id", "hardening"),
        beachhead=Beachhead.LINUX,
        operator=OperatorMode.PROVISIONING,
        automation_root=automation_root,
        graph_path=fixture_graph,
        ledger_root=tmp_path / "ledgers",
        runner=runner,
        **kwargs,
    )
    return orch, runner


# ---------------------------------------------------------------------------
# Ledger integrity (C4)
# ---------------------------------------------------------------------------

def test_ledger_integrity_roundtrip_and_tamper(tmp_path: Path, monkeypatch) -> None:
    ledger = CredentialLedger("crypto-eng", root=tmp_path)
    ledger.put(Credential(name="seed", username="u", password="p"))
    assert (tmp_path / "crypto-eng" / "key.bin").is_file()

    reloaded = CredentialLedger("crypto-eng", root=tmp_path)
    assert reloaded.get("seed").password == "p"

    path = tmp_path / "crypto-eng" / "creds.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["credentials"]["seed"]["password"] = "evil"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(crypto.IntegrityError):
        CredentialLedger("crypto-eng", root=tmp_path)

    monkeypatch.setenv("REDSTRIKE_LEDGER_UNVERIFIED", "1")
    overridden = CredentialLedger("crypto-eng", root=tmp_path)
    assert overridden.get("seed").password == "evil"


def test_ledger_legacy_file_upgrades_with_seal(tmp_path: Path) -> None:
    engagement = tmp_path / "legacy-eng"
    engagement.mkdir(parents=True)
    (engagement / "creds.json").write_text(
        json.dumps({"engagement_id": "legacy-eng", "credentials": {"old": {"username": "u"}}}),
        encoding="utf-8",
    )
    ledger = CredentialLedger("legacy-eng", root=tmp_path)
    assert ledger.get("old").username == "u"
    ledger.put(Credential(name="new", username="u2"))
    sealed = json.loads((engagement / "creds.json").read_text(encoding="utf-8"))
    assert sealed["integrity"]["algo"] == "hmac-sha256"


@pytest.mark.skipif(not crypto.encryption_available(), reason="cryptography not installed")
def test_ledger_encrypted_at_rest(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REDSTRIKE_LEDGER_ENCRYPT", "1")
    ledger = CredentialLedger("enc-eng", root=tmp_path)
    ledger.put(Credential(name="seed", username="u", password="super-secret"))
    raw = (tmp_path / "enc-eng" / "creds.json").read_text(encoding="utf-8")
    assert "encrypted" in raw and "super-secret" not in raw
    reloaded = CredentialLedger("enc-eng", root=tmp_path)
    assert reloaded.get("seed").password == "super-secret"


def test_explicit_approvals_are_audited(tmp_path: Path) -> None:
    session = CampaignSession("audit-eng", beachhead="windows", profile="gated", ledger_root=tmp_path)
    session.state.approve("dcsync", note="approved by operator")
    session.store.save(session.state)
    reloaded = EngagementStore("audit-eng", root=tmp_path).load()
    assert reloaded is not None
    assert reloaded.approvals and reloaded.approvals[-1]["gate"] == "dcsync"
    assert "approved by operator" in reloaded.approvals[-1]["note"]
    assert reloaded.approvals[-1]["ts"]


# ---------------------------------------------------------------------------
# Secrets: extraction, scrubbing, redaction
# ---------------------------------------------------------------------------

def test_extract_kerberoast_secrets() -> None:
    found = extract_secrets(KERBEROAST_OUTPUT)
    kerb = [item for item in found if item.kind == "kerberoast"]
    assert kerb and kerb[0].username == "svc_sql"
    assert kerb[0].value.startswith("$krb5tgs$23$")


def test_extract_secretsdump_and_keys() -> None:
    text = (
        "CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
        "31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "Rubeus finished: /rc4:5f4dcc3b5aa765d61d8327deb882cf99\n"
    )
    found = extract_secrets(text)
    ntlm = [item for item in found if item.kind == "ntlm" and item.username == "Administrator"]
    assert ntlm and ntlm[0].value == "31d6cfe0d16ae931b73c59d7e0c089c0"
    rc4 = [item for item in found if item.kind == "rc4"]
    assert rc4 and rc4[0].value == "5f4dcc3b5aa765d61d8327deb882cf99"


def test_scrub_output_masks_secrets(monkeypatch) -> None:
    monkeypatch.delenv("REDSTRIKE_RAW_OUTPUT", raising=False)
    scrubbed = scrub_output(KERBEROAST_OUTPUT)
    assert "$krb5tgs$" not in scrubbed
    assert "[REDACTED:kerberoast]" in scrubbed
    monkeypatch.setenv("REDSTRIKE_RAW_OUTPUT", "1")
    assert raw_output_requested() is True
    assert scrub_output(KERBEROAST_OUTPUT) == KERBEROAST_OUTPUT


def test_redact_argv_covers_more_secret_flags() -> None:
    redacted = redact_argv(
        ["certipy", "req", "-pfx-password", "s3cret", "--aesKey", "aa11", "-K", "bb22"]
    )
    assert redacted[3] == "***REDACTED***"
    assert redacted[5] == "***REDACTED***"
    assert redacted[7] == "***REDACTED***"
    inline = redact_argv(["Rubeus.exe", "asktgt", "/aes256:deadbeef", "/des:cafe"])
    assert inline[2] == "/aes256:***REDACTED***"
    assert inline[3] == "/des:***REDACTED***"
    # non-secret flags are untouched
    assert redact_argv(["nxc", "smb", "--shares", "host"]) == ["nxc", "smb", "--shares", "host"]


# ---------------------------------------------------------------------------
# Runner: timeout kills the process tree
# ---------------------------------------------------------------------------

def test_runner_timeout_kills_child_tree() -> None:
    runner = CommandRunner()
    started = time.monotonic()
    result = runner.run(
        ["python", "-c", "import time; time.sleep(30)"], timeout_seconds=1
    )
    elapsed = time.monotonic() - started
    assert result.return_code == 124
    assert result.timed_out is True
    assert elapsed < 15  # killed promptly, not waited out


# ---------------------------------------------------------------------------
# Graph schema: depends_on / when / timeout / teardown / targets
# ---------------------------------------------------------------------------

def test_graph_dependency_validation(tmp_path: Path) -> None:
    bad_ref = tmp_path / "bad-ref.yaml"
    bad_ref.write_text(
        "version: 1\nname: x\nnodes:\n"
        "  - id: A\n    phase: 1\n    title: a\n    path: direct\n    stub: true\n    depends_on: [GHOST]\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown node 'GHOST'"):
        load_campaign_graph(bad_ref)

    cycle = tmp_path / "cycle.yaml"
    cycle.write_text(
        "version: 1\nname: x\nnodes:\n"
        "  - id: A\n    phase: 1\n    title: a\n    path: direct\n    stub: true\n    depends_on: [B]\n"
        "  - id: B\n    phase: 2\n    title: b\n    path: direct\n    stub: true\n    depends_on: [A]\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="cycle"):
        load_campaign_graph(cycle)


def test_graph_bad_when_key_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad-when.yaml"
    path.write_text(
        "version: 1\nname: x\nnodes:\n"
        "  - id: A\n    phase: 1\n    title: a\n    path: direct\n    stub: true\n"
        "    when:\n      sometimes: [B]\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported keys"):
        load_campaign_graph(path)


# ---------------------------------------------------------------------------
# Orchestrator: deps, resume, stop_on_failure, scope, secrets, teardown
# ---------------------------------------------------------------------------

def _base_outputs(base_stdout: str = KERBEROAST_OUTPUT) -> dict[str, CommandResult]:
    return {
        "base.sh": _ok(["s/base.sh"], base_stdout),
        "dep.sh": _ok(["s/dep.sh"], "DEP_OK\n"),
        "cond.sh": _ok(["s/cond.sh"], "COND_OK\n"),
        "td.sh": _ok(["s/td.sh"], "TD_OK\n"),
        "certipy": _ok(["certipy"], "SCOPED_OK\n"),
    }


def test_dependency_gate_skips_when_dep_unverified(tmp_path: Path, automation_root: Path, fixture_graph: Path) -> None:
    outputs = _base_outputs(base_stdout="no marker here\n")  # BASE fails verification
    orch, _ = _orchestrator(tmp_path, automation_root, fixture_graph, outputs, node_ids="BASE,DEP,COND")
    results = orch.run("1-5", dry_run=False, stop_on_hitl=False)
    by_id = {r.plan.node_id: r for r in results}
    assert by_id["BASE"].verified is False
    assert by_id["DEP"].skipped is True
    assert "did not verify" in (by_id["DEP"].skip_reason or "")
    assert by_id["COND"].skipped is True
    assert "when.verified not met" in (by_id["COND"].skip_reason or "")


def test_secrets_parsed_into_ledger(tmp_path: Path, automation_root: Path, fixture_graph: Path) -> None:
    orch, _ = _orchestrator(tmp_path, automation_root, fixture_graph, _base_outputs(), node_ids="BASE")
    results = orch.run("1", dry_run=False, stop_on_hitl=False)
    assert results[0].verified is True
    cred = orch.ledger.get("krb_hash")
    assert cred is not None
    assert cred.username == "svc_sql"
    assert cred.nt_hash and cred.nt_hash.startswith("$krb5tgs$")
    assert "kerberoast" in (cred.notes or "")


def test_resume_skips_previously_verified(tmp_path: Path, automation_root: Path, fixture_graph: Path) -> None:
    orch, _runner = _orchestrator(tmp_path, automation_root, fixture_graph, _base_outputs(), node_ids="BASE,DEP")
    first = orch.run("1-5", dry_run=False, stop_on_hitl=False)
    assert all(r.verified or r.skipped for r in first)
    assert "BASE" in orch.state.completed_nodes

    orch2, runner2 = _orchestrator(
        tmp_path, automation_root, fixture_graph, _base_outputs(), node_ids="BASE,DEP",
        engagement_id="hardening",
    )
    resumed = orch2.run("1-5", dry_run=False, stop_on_hitl=False, resume=True)
    by_id = {r.plan.node_id: r for r in resumed}
    assert by_id["BASE"].skipped is True and "already verified" in (by_id["BASE"].skip_reason or "")
    assert runner2.calls == []  # nothing executed on resume


def test_stop_on_failure_skips_remaining(tmp_path: Path, automation_root: Path, fixture_graph: Path) -> None:
    outputs = _base_outputs(base_stdout="no marker\n")
    orch, _ = _orchestrator(tmp_path, automation_root, fixture_graph, outputs, node_ids="BASE,DEP,COND")
    results = orch.run("1-5", dry_run=False, stop_on_hitl=False, stop_on_failure=True)
    by_id = {r.plan.node_id: r for r in results}
    assert by_id["BASE"].verified is False
    assert by_id["DEP"].skipped is True
    assert "stop_on_failure" in (by_id["DEP"].skip_reason or "")
    assert by_id["COND"].skipped is True


def test_scope_blocks_live_target_without_policy(tmp_path: Path, automation_root: Path, fixture_graph: Path) -> None:
    orch, runner = _orchestrator(tmp_path, automation_root, fixture_graph, _base_outputs(), node_ids="SCOPED")
    results = orch.run("4", dry_run=False, stop_on_hitl=False)
    assert results[0].skipped is True
    assert "requires a scope policy" in (results[0].skip_reason or "")
    assert runner.calls == []

    dry = orch.run("4", dry_run=True, stop_on_hitl=False)
    assert dry[0].dry_run is True  # previews are not blocked


def test_scope_allows_in_policy_target(tmp_path: Path, automation_root: Path, fixture_graph: Path) -> None:
    policy = ScopePolicy(
        allowed_targets=["10.0.0.0/24"], allowed_domains=["corp.local"], allow_high_risk=True
    )
    orch, _ = _orchestrator(
        tmp_path, automation_root, fixture_graph, _base_outputs(), node_ids="SCOPED",
        scope_policy=policy,
    )
    results = orch.run("4", dry_run=False, stop_on_hitl=False)
    assert results[0].verified is True


def test_scope_blocks_out_of_policy_target(tmp_path: Path, automation_root: Path, fixture_graph: Path) -> None:
    policy = ScopePolicy(allowed_targets=["10.9.9.0/24"], allowed_domains=["corp.local"], allow_high_risk=True)
    orch, runner = _orchestrator(
        tmp_path, automation_root, fixture_graph, _base_outputs(), node_ids="SCOPED",
        scope_policy=policy,
    )
    results = orch.run("4", dry_run=False, stop_on_hitl=False)
    assert results[0].skipped is True
    assert "outside allowed scope" in (results[0].skip_reason or "")
    assert runner.calls == []


def test_teardown_registered_and_persisted(tmp_path: Path, automation_root: Path, fixture_graph: Path) -> None:
    orch, _ = _orchestrator(tmp_path, automation_root, fixture_graph, _base_outputs(), node_ids="TD")
    results = orch.run("5", dry_run=False, stop_on_hitl=False)
    assert results[0].verified is True
    queue_file = orch.store.dir / "teardown.json"
    assert queue_file.is_file()
    queue = load_queue(queue_file)
    assert len(queue.all_actions) == 1
    assert queue.all_actions[0].command == ["rm", "-f", "/tmp/rs-test-artifact"]


def test_per_node_timeout_passed_to_runner(tmp_path: Path, automation_root: Path, fixture_graph: Path) -> None:
    class TimeoutWatcher(ScriptedRunner):
        def __init__(self, outputs):
            super().__init__(outputs)
            self.kwargs_seen: list[dict] = []

        def run(self, argv, **kwargs):
            self.kwargs_seen.append(kwargs)
            return super().run(argv, **kwargs)

    runner = TimeoutWatcher(_base_outputs())
    orch = CampaignOrchestrator(
        engagement_id="timeout-eng",
        beachhead=Beachhead.LINUX,
        operator=OperatorMode.PROVISIONING,
        automation_root=automation_root,
        graph_path=fixture_graph,
        ledger_root=tmp_path / "ledgers",
        runner=runner,
        node_ids="TD",
    )
    orch.run("5", dry_run=False, stop_on_hitl=False)
    assert runner.kwargs_seen == [{"timeout_seconds": 30}]


# ---------------------------------------------------------------------------
# Teardown persistence + report + small fixes
# ---------------------------------------------------------------------------

def test_teardown_queue_persistence_roundtrip(tmp_path: Path) -> None:
    queue = TeardownQueue()
    queue.register("node-a", "host1", ["rm", "x"], "cleanup a")
    action = queue.register("node-b", "host2", ["rm", "y"], "cleanup b")
    action.executed = True
    action.success = True
    path = tmp_path / "teardown.json"
    save_queue(path, queue)
    loaded = load_queue(path)
    assert [a.name for a in loaded.all_actions] == ["node-a", "node-b"]
    assert loaded.all_actions[1].executed is True
    assert len(loaded.pending) == 1


def test_engagement_report_bundle_and_masking(tmp_path: Path) -> None:
    from redstrike.reporting.engagement import (
        load_engagement_bundle,
        render_engagement_json,
        render_engagement_markdown,
    )

    root = tmp_path / "engagements"
    session = CampaignSession("report-eng", beachhead="windows", profile="gated", ledger_root=root)
    session.state.approve("dcsync", note="ok")
    session.store.save(session.state)
    ledger = CredentialLedger("report-eng", root=root)
    ledger.put(Credential(name="seed", username="analyst", password="hunter2", nt_hash="a" * 32))

    bundle = load_engagement_bundle("report-eng", root=root)
    md = render_engagement_markdown(bundle)
    assert "RedStrike Engagement Report" in md
    assert "hunter2" not in md and "***" in md or "…" in md
    assert "- [x]" not in md  # no fabricated teardown entries

    json_bundle = render_engagement_json(bundle)
    masked = next(entry for entry in json_bundle["credentials"] if entry["name"] == "seed")
    assert masked["has_password"] is True
    assert "password" not in masked

    raw = load_engagement_bundle("report-eng", root=root, include_secrets=True)
    raw_cred = next(entry for entry in raw["credentials"] if entry["name"] == "seed")
    assert raw_cred["password"] == "hunter2"


def test_jobs_completed_dedupe_ttl() -> None:
    from redstrike.api.jobs import JobStatus, JobStore

    release = threading.Event()
    started = threading.Event()

    def worker(_request: ADRequest) -> OperationResponse:
        started.set()
        release.wait(timeout=5)
        return OperationResponse(success=True)

    request = ADRequest(target="host01", domain="corp.local")
    store = JobStore(completed_ttl_seconds=0.0)
    job1 = store.create("domain_users", request, worker)
    assert started.wait(timeout=5)
    duplicate_running = store.create("domain_users", request, worker)
    assert duplicate_running.id == job1.id  # RUNNING still dedupes

    release.set()
    deadline = time.time() + 5
    while store.get(job1.id).status is not JobStatus.COMPLETED and time.time() < deadline:
        time.sleep(0.02)
    assert store.get(job1.id).status is JobStatus.COMPLETED

    job2 = store.create("domain_users", request, worker)
    assert job2.id != job1.id  # TTL=0 disables completed dedupe (fresh run)


def test_verify_expected_error_token_must_be_bounded() -> None:
    vague = verify_step_output(
        node_id="T999", return_code=1, stdout="NT_STATUS_ACCESS_DENIED", expected_errors=["denied"]
    )
    assert vague.verified is False  # short token no longer waives a different failure
    exact = verify_step_output(
        node_id="T028",
        return_code=0,
        stdout="NT_STATUS_ACCESS_DENIED\nT028_OK",
        expected_errors=["NT_STATUS_ACCESS_DENIED"],
    )
    assert exact.verified is True


def test_http_call_spec_never_ssh_wrapped() -> None:
    spec = CallSpec(kind=CallKind.HTTP, url="http://example/api", method="GET")
    plan = StepPlan(
        node_id="H1",
        title="http node",
        phase=1,
        path=ExecutionPath.WS01,
        beachhead=Beachhead.WINDOWS,
        argv=spec.to_display_command(),
        uses_ws01_exec=False,
        mechanism="intent:http.test",
        script="",
        requires_cred=None,
        produces_cred=None,
        call_spec=spec,
    )
    assert argv_for_plan(plan) is spec


def test_parse_branches_semantics_preserved() -> None:
    assert parse_branches(None) == {"spine"}
    assert parse_branches("a,b") == {"A", "B"}
    assert parse_branches("SQL-AI") == {"sql-ai"}
    assert parse_branches("all") == {"spine", "A", "B", "C", "D", "E", "F", "G", "H", "sql-ai"}


def test_cli_profile_choices_cover_policy_profiles() -> None:
    from redstrike.cli.campaign import profile_choices

    choices = profile_choices()
    assert {"validate-gated", "adcs-deep", "forest-trust-review"} <= set(choices)
    assert "ungated" in choices  # alias exposed


def test_scope_policy_methods() -> None:
    policy = load_scope_policy(None, profile="gated")
    policy.assert_target_in_scope("anything")  # empty lists: nothing to check
    strict = ScopePolicy(allowed_targets=["10.0.0.0/24"], allowed_domains=["corp.local"])
    strict.assert_target_in_scope("10.0.0.7", "corp.local")
    with pytest.raises(PermissionError):
        strict.assert_target_in_scope("203.0.113.5")
    with pytest.raises(PermissionError):
        strict.assert_target_in_scope("10.0.0.7", "evil.example")


# ---------------------------------------------------------------------------
# Leftover 1: evidence/findings persistence + report join
# ---------------------------------------------------------------------------

def test_service_persists_evidence_and_findings(tmp_path: Path, monkeypatch) -> None:
    from redstrike.ad.service import ActiveDirectoryAssessmentService
    from redstrike.reporting.engagement import (
        load_engagement_bundle,
        render_engagement_markdown,
    )
    from redstrike.runtime.evidence_store import EvidenceStore

    monkeypatch.setenv("REDSTRIKE_HOME", str(tmp_path))

    class StubRunner:
        def run(self, argv, **kwargs) -> CommandResult:
            return CommandResult(
                command=list(argv),
                return_code=0,
                stdout=(
                    "* Lockout threshold: None\n"
                    "$krb5tgs$23$*svc$CORP.LOCAL$spn*$aa11bb22cc33dd44ee55ff6677889900\n"
                ),
                stderr="",
                duration_seconds=0.0,
            )

    service = ActiveDirectoryAssessmentService(
        load_scope_policy(None, profile="gated"), runner=StubRunner()
    )
    request = ADRequest(target="dc01.corp.local", domain="corp.local", engagement_id="ev-eng")
    response = service.password_policy(request)
    assert response.findings and response.findings[0].risk.value == "high"

    store = EvidenceStore("ev-eng")
    assert store.persisted()
    assert len(store.evidence()) == 1
    assert len(store.findings()) == 1

    CampaignSession("ev-eng", ledger_root=tmp_path / "engagements")
    bundle = load_engagement_bundle("ev-eng", root=tmp_path / "engagements")
    assert bundle["summary"]["findings"] == 1
    assert bundle["summary"]["evidence"] == 1

    markdown = render_engagement_markdown(bundle)
    assert "lockout threshold" in markdown.lower()
    assert "$krb5tgs$" not in markdown  # raw output scrubbed in the report

    raw = load_engagement_bundle("ev-eng", root=tmp_path / "engagements", include_secrets=True)
    assert "$krb5tgs$" in raw["evidence"][0]["raw_output"]


def test_service_without_engagement_id_persists_nothing(tmp_path: Path, monkeypatch) -> None:
    from redstrike.ad.service import ActiveDirectoryAssessmentService

    monkeypatch.setenv("REDSTRIKE_HOME", str(tmp_path))

    class StubRunner:
        def run(self, argv, **kwargs) -> CommandResult:
            return CommandResult(command=list(argv), return_code=0, stdout="x", stderr="", duration_seconds=0.0)

    service = ActiveDirectoryAssessmentService(
        load_scope_policy(None, profile="gated"), runner=StubRunner()
    )
    service.domain_users(ADRequest(target="dc01.corp.local", domain="corp.local"))
    assert not (tmp_path / "engagements").exists()


# ---------------------------------------------------------------------------
# Leftover 2: non-idempotent nodes refuse automatic re-runs
# ---------------------------------------------------------------------------

def test_non_idempotent_unverified_attempt_guarded(
    tmp_path: Path, automation_root: Path, fixture_graph: Path
) -> None:
    outputs = _base_outputs()
    outputs["nonidem.sh"] = _ok(["s/nonidem.sh"], "no marker\n")
    orch, _runner = _orchestrator(tmp_path, automation_root, fixture_graph, outputs, node_ids="NONIDEM")
    first = orch.run("6", dry_run=False, stop_on_hitl=False)
    assert first[0].verified is False
    assert orch.state.attempted_nodes["NONIDEM"]["verified"] is False

    orch2, runner2 = _orchestrator(tmp_path, automation_root, fixture_graph, outputs, node_ids="NONIDEM")
    guarded = orch2.run("6", dry_run=False, stop_on_hitl=False, resume=True)
    assert guarded[0].skipped is True
    assert "non-idempotent" in (guarded[0].skip_reason or "")
    assert runner2.calls == []  # never re-executed automatically

    forced = orch2.run("6", dry_run=False, stop_on_hitl=False, resume=True, rerun=True)
    assert runner2.calls  # --rerun forces it
    assert forced[0].verified is False  # still fails, but it RAN


def test_idempotent_default_reruns_after_unverified(
    tmp_path: Path, automation_root: Path, fixture_graph: Path
) -> None:
    outputs = _base_outputs(base_stdout="no marker\n")
    orch, _runner = _orchestrator(tmp_path, automation_root, fixture_graph, outputs, node_ids="BASE")
    orch.run("1", dry_run=False, stop_on_hitl=False)  # unverified attempt recorded

    orch2, runner2 = _orchestrator(tmp_path, automation_root, fixture_graph, outputs, node_ids="BASE")
    again = orch2.run("1", dry_run=False, stop_on_hitl=False, resume=True)
    assert runner2.calls  # idempotent/unknown nodes still re-run on resume
    assert again[0].verified is False


# ---------------------------------------------------------------------------
# Leftover 3: shared SQLite rate window
# ---------------------------------------------------------------------------

def test_sqlite_rate_window_shared_across_instances(tmp_path: Path) -> None:
    from redstrike.api.ratelimit import SqliteRateWindow
    from redstrike.core.errors import RateLimitExceededError

    db = tmp_path / "rl.db"
    first = SqliteRateWindow(db)
    second = SqliteRateWindow(db)
    first.check("caller|/ad/users", 2, 60.0)
    second.check("caller|/ad/users", 2, 60.0)  # shared budget
    with pytest.raises(RateLimitExceededError):
        first.check("caller|/ad/users", 2, 60.0)
    second.check("other-caller|/ad/users", 2, 60.0)  # independent key


def test_api_rate_limit_uses_shared_db(tmp_path: Path, monkeypatch) -> None:
    from fastapi.testclient import TestClient
    from test_api import _OkService

    from redstrike.api import server

    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        'allowed_targets: ["10.0.0.0/24"]\nallowed_domains: ["corp.local"]\n'
        "rate_limit_requests: 2\nrate_limit_window_seconds: 60\n",
        encoding="utf-8",
    )
    app = server.create_app(scope_path=str(scope), rate_limit_db=str(tmp_path / "rl.db"))
    client = TestClient(app)
    payload = {"target": "10.0.0.5", "domain": "corp.local", "mode": "observe"}
    assert client.post("/ad/users", json=payload).status_code == 200
    assert client.post("/ad/users", json=payload).status_code == 200
    assert client.post("/ad/users", json=payload).status_code == 429


# ---------------------------------------------------------------------------
# Leftover 4: request-body size cap
# ---------------------------------------------------------------------------

def test_api_rejects_oversized_body(monkeypatch) -> None:
    from fastapi.testclient import TestClient
    from test_api import _OkService

    from redstrike.api import server

    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    monkeypatch.setenv("REDSTRIKE_MAX_BODY_BYTES", "256")
    client = TestClient(server.create_app())

    oversized = client.post("/campaign/status", json={"engagement_id": "x", "objective": "y" * 400})
    assert oversized.status_code == 413
    assert "exceeds" in oversized.json()["detail"]

    assert client.get("/health").status_code == 200  # normal traffic unaffected
