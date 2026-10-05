from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from test_c2_integration import MockC2Client

from redstrike.api import server
from redstrike.c2.stack import C2StackClient
from redstrike.core.models import C2Backend, OperationResponse
from redstrike.core.runner import CommandRunner
from redstrike.runtime.beachhead import Beachhead
from redstrike.runtime.graph import load_campaign_graph
from redstrike.runtime.hitl import EngagementStore
from redstrike.runtime.orchestrator import CampaignOrchestrator
from redstrike.runtime.session import CampaignSession

FLEET = {
    "count": 2,
    "sessions": [
        {
            "id": "4555ab0e", "backend": "havoc", "hostname": "WINDOWS-HOST",
            "username": "operator", "os": "Windows 10", "is_alive": True,
        },
        {
            "id": "a5d9dc29", "backend": "sliver", "hostname": "windows",
            "username": "WIN-TARGET\\operator", "os": "windows/amd64", "is_alive": False,
        },
    ],
    "backends": {
        "havoc": {"ok": True, "count": 1},
        "sliver": {"ok": True, "count": 1},
        "mythic": {"ok": False, "error": "psql down"},
    },
}


class _OkService:
    def __init__(self, _policy) -> None:
        pass

    def _ok(self, _request):
        return OperationResponse(success=True)

    domain_users = _ok
    domain_groups = _ok
    domain_computers = _ok
    password_policy = _ok
    shares = _ok
    asrep_roastable = _ok
    kerberoastable = _ok
    delegation = _ok
    admin_count = _ok
    adcs_enum = _ok


# ---------------------------------------------------------------------------
# C2StackClient
# ---------------------------------------------------------------------------

def test_stack_sessions_filter_and_select():
    client = C2StackClient(endpoint="http://portal:8000")
    with patch.object(client, "_get_json", return_value=FLEET):
        data = client.sessions(backend="havoc")
        assert [s["id"] for s in data["sessions"]] == ["4555ab0e"]
        assert client.backends()["mythic"]["ok"] is False
        picked = client.select_session("havoc")
        assert picked is not None and picked["id"] == "4555ab0e"
        # dead sliver session is skipped when alive_only (default)
        assert client.select_session("sliver") is None
        assert client.select_session("sliver", alive_only=False)["id"] == "a5d9dc29"
        assert client.select_session("havoc", hostname="nope") is None


def test_stack_havoc_build_decodes_base64():
    client = C2StackClient(endpoint="http://portal:8000")
    response = {
        "ok": True, "filename": "demon.x64.exe", "size": 3,
        "base64": base64.b64encode(b"MZ!").decode("ascii"),
        "console": ["done"],
    }
    with patch.object(client, "_post_json", return_value=response) as mock_post:
        data = client.build_havoc(arch="x64", format="Windows Exe", sleep=7, jitter=3)
        assert data["payload"] == b"MZ!"
        assert "base64" not in data
        assert mock_post.call_args[0][0] == "/api/ops/havoc/build"
        assert mock_post.call_args[0][1]["sleep"] == 7


def test_stack_adaptix_build_pins_jitter_zero():
    client = C2StackClient(endpoint="http://portal:8000")
    response = {"ok": True, "filename": "agent.x64.exe", "size": 2,
                "base64": base64.b64encode(b"MZ").decode("ascii")}
    with patch.object(client, "_post_json", return_value=response) as mock_post:
        data = client.build_adaptix()
        assert data["payload"] == b"MZ"
        assert mock_post.call_args[0][0] == "/api/ops/adaptix/agent"
        # jitter is hard-pinned: the snapshot corrupts non-zero jitter (PR #379)
        assert mock_post.call_args[0][1]["jitter"] == 0


def test_stack_mythic_build_filters_overrides():
    client = C2StackClient(endpoint="http://portal:8000")
    with patch.object(client, "_post_json", return_value={"ok": True, "uuid": "u1"}) as mock_post:
        client.build_mythic(output_type="Shellcode", bogus_field="x")
        sent = mock_post.call_args[0][1]
        assert sent == {"output_type": "Shellcode"}


def test_stack_mythic_download_writes_file(tmp_path: Path):
    client = C2StackClient(endpoint="http://portal:8000")
    dest = tmp_path / "apollo.exe"
    with patch.object(client, "_get_bytes", return_value=(b"MZ payload", None)):
        data = client.mythic_download("u1", dest=dest)
        assert data["ok"] is True
        assert dest.read_bytes() == b"MZ payload"
        assert data["path"] == str(dest)


def test_stack_stage_bytes_multipart():
    client = C2StackClient(endpoint="http://portal:8000")
    with patch.object(client, "_request_json", return_value={"ok": True, "agent_file_id": "f1"}) as mock_req:
        data = client.stage_bytes(b"CAFEBABE", "test.o")
        assert data["agent_file_id"] == "f1"
        kwargs = mock_req.call_args.kwargs
        assert kwargs["headers"]["Content-Type"].startswith("multipart/form-data; boundary=")
        assert b'name="file"; filename="test.o"' in kwargs["body"]
        assert b"CAFEBABE" in kwargs["body"]


def test_stack_stage_file_missing(tmp_path: Path):
    client = C2StackClient(endpoint="http://portal:8000")
    data = client.stage_file(tmp_path / "nope.bin")
    assert data["ok"] is False
    assert "cannot read" in data["error"]


def test_stack_task_and_probe_payloads():
    client = C2StackClient(endpoint="http://portal:8000")
    with patch.object(client, "_post_json", return_value={"ok": True}) as mock_post:
        client.task("havoc", "d1", "whoami", wait=10)
        assert mock_post.call_args[0][0] == "/api/ops/task"
        assert mock_post.call_args[0][1] == {
            "session_id": "d1", "backend": "havoc", "command": "whoami", "wait": 10,
        }
        client.task("mythic", "5", "whoami", callback_id=5)
        assert mock_post.call_args[0][1]["callback_id"] == 5
        client.probe_redirector("/gateway/v1/telemetry", headers={"X-Request-ID": "cadre-c2"})
        assert mock_post.call_args[0][0] == "/api/ops/probe"


def test_stack_transport_error_is_honest():
    client = C2StackClient(endpoint="http://127.0.0.1:9")  # nothing listens here
    data = client.status()
    assert data["ok"] is False
    assert "error" in data


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_c2_cli_status(capsys):
    from redstrike.cli.c2 import main as c2_main

    payload = {
        "docker_available": True,
        "services": {
            "havoc": {"state": "running", "port_live": True, "uri_prefix": "/edge/cache/assets"},
        },
    }
    with patch.object(C2StackClient, "status", return_value=payload):
        assert c2_main(["status"]) == 0
    out = capsys.readouterr().out
    assert "havoc" in out and "running" in out


def test_c2_cli_build_havoc_writes_payload(tmp_path: Path, capsys):
    from redstrike.cli.c2 import main as c2_main

    out = tmp_path / "demon.exe"
    response = {"ok": True, "filename": "demon.x64.exe", "size": 2, "payload": b"MZ"}
    with patch.object(C2StackClient, "build_havoc", return_value=response):
        rc = c2_main(["build", "--backend", "havoc", "--out", str(out)])
    assert rc == 0
    assert out.read_bytes() == b"MZ"


def test_c2_cli_build_failure_returns_1(capsys):
    from redstrike.cli.c2 import main as c2_main

    with patch.object(C2StackClient, "build_havoc", return_value={"ok": False, "error": "boom"}):
        assert c2_main(["build", "--backend", "havoc"]) == 1
    assert "boom" in capsys.readouterr().out


def test_c2_cli_sessions_marks_unreachable_backend(capsys):
    from redstrike.cli.c2 import main as c2_main

    with patch.object(C2StackClient, "sessions", return_value=FLEET):
        assert c2_main(["sessions"]) == 0
    out = capsys.readouterr().out
    assert "mythic" in out and "psql down" in out
    assert "2 session(s)" in out


# ---------------------------------------------------------------------------
# API routes (stack surface + auth)
# ---------------------------------------------------------------------------

def test_api_stack_routes(monkeypatch):
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    app = server.create_app()
    client = TestClient(app)

    with patch.object(C2StackClient, "sessions", return_value=FLEET):
        resp = client.post("/c2/stack/sessions", json={"backend": "havoc"})
    assert resp.status_code == 200
    assert resp.json()["sessions"][0]["id"] == "4555ab0e"

    with patch.object(C2StackClient, "probe_redirector", return_value={"ok": True, "verdict": "decoy"}):
        resp = client.post("/c2/stack/probe", json={"url_path": "/"})
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "decoy"

    with patch.object(C2StackClient, "build_havoc", return_value={"ok": True, "payload": b"MZ", "size": 2}):
        resp = client.post("/c2/stack/build", json={"backend": "havoc", "out": None})
    body = resp.json()
    assert body["ok"] is True
    assert body["payload_b64"] == base64.b64encode(b"MZ").decode("ascii")


def test_api_stack_routes_require_key_remotely(monkeypatch):
    monkeypatch.setattr(server, "ActiveDirectoryAssessmentService", _OkService)
    app = server.create_app(api_key="secret")
    client = TestClient(app)

    assert client.post("/c2/stack/status", json={}).status_code == 401
    assert client.post("/campaign/status", json={"engagement_id": "x"}).status_code == 401
    assert client.post("/c2/shell", json={
        "session_id": "s", "command": "whoami",
    }).status_code == 401

    with patch.object(C2StackClient, "status", return_value={"ok": True, "services": {"havoc": {}}}):
        resp = client.post("/c2/stack/status", json={}, headers={"X-API-Key": "secret"})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Orchestrator resolution
# ---------------------------------------------------------------------------

def test_orchestrator_resolves_missing_session():
    orch = CampaignOrchestrator(
        engagement_id="test-c2-resolve",
        beachhead=Beachhead.SESSION,
        automation_root=Path("."),
        c2_enabled=True,
        c2_backend=C2Backend.HAVOC,
        runner=CommandRunner(c2_client=MockC2Client(C2Backend.HAVOC)),
    )
    assert orch.c2_session_id is None
    orch._resolve_c2()
    assert orch.c2_session_id == "test-session-uuid-1"
    assert orch.router.c2_session_id == "test-session-uuid-1"
    assert orch.c2_backend == C2Backend.HAVOC


def test_orchestrator_auto_backend_from_fleet():
    orch = CampaignOrchestrator(
        engagement_id="test-c2-auto",
        beachhead=Beachhead.SESSION,
        automation_root=Path("."),
        c2_enabled=True,
        c2_backend="auto",
        c2_endpoint="http://portal:8000",
        runner=CommandRunner(c2_client=MockC2Client(C2Backend.HAVOC)),
    )
    assert orch.c2_backend_auto is True
    with patch.object(C2StackClient, "sessions", return_value=FLEET):
        orch._resolve_c2()
    assert orch.c2_backend == C2Backend.HAVOC  # first live backend in preference order
    assert orch.router.c2_backend == C2Backend.HAVOC
    assert orch.c2_session_id == "test-session-uuid-1"


def test_orchestrator_auto_backend_falls_back_when_stack_down():
    orch = CampaignOrchestrator(
        engagement_id="test-c2-auto-down",
        beachhead=Beachhead.SESSION,
        automation_root=Path("."),
        c2_enabled=True,
        c2_backend="auto",
        c2_endpoint="http://127.0.0.1:9",
        runner=CommandRunner(c2_client=MockC2Client(C2Backend.SLIVER)),
    )
    with patch.object(C2StackClient, "sessions", return_value={"ok": False, "error": "unreachable"}):
        orch._resolve_c2()
    assert orch.c2_backend == C2Backend.SLIVER  # provisional default kept


# ---------------------------------------------------------------------------
# Core fixes (audit: C3 sticky approvals, M3 unknown gates)
# ---------------------------------------------------------------------------

def test_autonomous_auto_approvals_not_persisted(tmp_path: Path):
    session = CampaignSession(
        "test-autonomous-approvals",
        beachhead="windows",
        profile="autonomous",
        ledger_root=tmp_path,
    )
    # In-process: gates are approved so the run proceeds ungated.
    assert session.state.is_approved("dcsync") is True
    # On disk: no phantom approvals a later gated run would inherit.
    reloaded = EngagementStore("test-autonomous-approvals", root=tmp_path).load()
    assert reloaded is not None
    assert reloaded.approved_gates == []
    assert reloaded.is_approved("dcsync") is False


def test_explicit_approval_still_persists(tmp_path: Path):
    session = CampaignSession(
        "test-gated-approval",
        beachhead="windows",
        profile="gated",
        ledger_root=tmp_path,
    )
    session.state.approve("dcsync", note="operator approved")
    session.store.save(session.state)
    reloaded = EngagementStore("test-gated-approval", root=tmp_path).load()
    assert reloaded is not None
    assert reloaded.approved_gates == ["dcsync"]
    assert reloaded.is_approved("dcsync") is True


def test_graph_rejects_unknown_hitl_gate(tmp_path: Path):
    import pytest

    graph_yaml = tmp_path / "bad-gate.yaml"
    graph_yaml.write_text(
        "version: 1\n"
        "name: bad-gate\n"
        "nodes:\n"
        "  - id: X-1\n"
        "    phase: 1\n"
        "    title: node with an unapprovable gate\n"
        "    path: direct\n"
        "    hitl_gate: password_reset\n"
        "    stub: true\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="hitl_gate unknown"):
        load_campaign_graph(graph_yaml)
