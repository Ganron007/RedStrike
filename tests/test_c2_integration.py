from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from redstrike.c2.base import BaseC2Client
from redstrike.c2.meridian import MeridianClient
from redstrike.c2.sliver import SliverClient
from redstrike.core.models import (
    C2Backend,
    C2Session,
    C2TaskType,
    CallKind,
    CallSpec,
    CommandResult,
)
from redstrike.core.runner import CommandRunner
from redstrike.runtime.beachhead import (
    Beachhead,
    BeachheadRouter,
    ExecutionPath,
    StepPlan,
)
from redstrike.runtime.intents import IntentRegistry
from redstrike.runtime.orchestrator import CampaignOrchestrator
from redstrike.runtime.ws01_transport import argv_for_plan


class MockC2Client(BaseC2Client):
    """Test double for C2 backends."""

    def __init__(self, backend: C2Backend = C2Backend.SLIVER):
        self.backend = backend
        self.sessions = [
            C2Session(
                id="test-session-uuid-1",
                backend=backend,
                hostname="WS01",
                username="analyst_t1",
                os="windows",
                arch="amd64",
                transport="http",
                is_alive=True,
            )
        ]
        self.calls: list[tuple[str, dict]] = []

    def list_sessions(self) -> list[C2Session]:
        self.calls.append(("list_sessions", {}))
        return self.sessions

    def execute_assembly(
        self,
        session_id: str,
        assembly: str,
        args: list[str] | None = None,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        self.calls.append(("execute_assembly", {"session_id": session_id, "assembly": assembly, "args": args}))
        return CommandResult(
            command=["c2:mock", "execute-assembly", "--session", session_id, "--assembly", assembly] + (args or []),
            return_code=0,
            stdout="[*] Action: Kerberoasting\n[*] Hash: $krb5tgs$23$*...",
            stderr="",
            duration_seconds=0.5,
        )

    def shell(
        self,
        session_id: str,
        command: str,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        self.calls.append(("shell", {"session_id": session_id, "command": command}))
        return CommandResult(
            command=["c2:mock", "shell", "--session", session_id, command],
            return_code=0,
            stdout="whoami -> child\\analyst_t1",
            stderr="",
            duration_seconds=0.2,
        )

    def psexec(
        self,
        session_id: str,
        target: str,
        service_name: str,
        bin_path: str,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        self.calls.append(("psexec", {"session_id": session_id, "target": target, "service": service_name}))
        return CommandResult(
            command=["c2:mock", "psexec", "--session", session_id, target, service_name, bin_path],
            return_code=0,
            stdout="[+] Service installed and running.",
            stderr="",
            duration_seconds=1.0,
        )


def test_call_spec_model():
    """Verify CallSpec model serialization and display conversion."""
    argv_spec = CallSpec(kind=CallKind.ARGV, argv=["echo", "hello"])
    assert argv_spec.to_display_command() == ["echo", "hello"]

    c2_spec = CallSpec(
        kind=CallKind.C2,
        c2_backend=C2Backend.SLIVER,
        c2_task_type=C2TaskType.EXECUTE_ASSEMBLY,
        session_id="session-123",
        assembly="Rubeus.exe",
        args=["kerberoast", "/domain:cadre.local"],
    )
    assert c2_spec.to_display_command() == [
        "c2:sliver",
        "execute_assembly",
        "--session",
        "session-123",
        "--assembly",
        "Rubeus.exe",
        "kerberoast",
        "/domain:cadre.local",
    ]


def test_c2_intent_registry_builders():
    """Verify IntentRegistry creates typed CallSpec for C2 intents."""
    registry = IntentRegistry()
    assert "c2.sliver.execute_assembly" in registry.known()
    assert "c2.sliver.psexec" in registry.known()
    assert "c2.meridian.task" in registry.known()

    spec = registry.build_spec(
        "c2.sliver.execute_assembly",
        {"session_id": "abc-1", "assembly": "Rubeus.exe", "args": ["kerberoast"]},
    )
    assert isinstance(spec, CallSpec)
    assert spec.kind == CallKind.C2
    assert spec.c2_backend == C2Backend.SLIVER
    assert spec.session_id == "abc-1"
    assert spec.assembly == "Rubeus.exe"


def test_command_runner_c2_dispatch():
    """Verify CommandRunner delegates C2 CallSpec to mock C2 adapter."""
    mock_client = MockC2Client()
    runner = CommandRunner(c2_client=mock_client)

    spec = CallSpec(
        kind=CallKind.C2,
        c2_backend=C2Backend.SLIVER,
        c2_task_type=C2TaskType.EXECUTE_ASSEMBLY,
        session_id="test-session-uuid-1",
        assembly="Rubeus.exe",
        args=["kerberoast"],
    )

    result = runner.run(spec)
    assert result.return_code == 0
    assert "Kerberoasting" in result.stdout
    assert len(mock_client.calls) == 1
    assert mock_client.calls[0][0] == "execute_assembly"


def test_beachhead_router_c2_session():
    """Verify BeachheadRouter maps session beachhead to C2_IMPLANT path."""
    router = BeachheadRouter(
        automation_root=Path("."),
        c2_enabled=True,
        c2_backend=C2Backend.SLIVER,
        c2_session_id="sess-xyz",
    )
    path = router.effective_path(
        declared_path="ws01",
        beachhead=Beachhead.SESSION,
    )
    assert path == ExecutionPath.C2_IMPLANT


def test_ws01_transport_c2_plan():
    """Verify argv_for_plan returns CallSpec directly for C2 execution path."""
    spec = CallSpec(
        kind=CallKind.C2,
        c2_backend=C2Backend.SLIVER,
        c2_task_type=C2TaskType.SHELL,
        session_id="s1",
        args=["whoami"],
    )
    plan = StepPlan(
        node_id="test-node",
        title="Test C2 Node",
        phase=1.0,
        path=ExecutionPath.C2_IMPLANT,
        beachhead=Beachhead.SESSION,
        argv=spec.to_display_command(),
        uses_ws01_exec=False,
        mechanism="c2:sliver",
        script="",
        requires_cred=None,
        produces_cred=None,
        call_spec=spec,
    )

    resolved = argv_for_plan(plan)
    assert isinstance(resolved, CallSpec)
    assert resolved.kind == CallKind.C2


def test_sliver_client_offline_fallback():
    """Verify SliverClient fails safely when binary is absent in test environment."""
    client = SliverClient(sliver_binary="/nonexistent/sliver-client")
    sessions = client.list_sessions()
    assert sessions == []

    res = client.execute_assembly("s1", "test.exe")
    assert res.return_code != 0
    assert "not found on PATH" in res.stderr


def test_meridian_client_cli_flow():
    """Verify MeridianClient queues an exec task and polls results via the CLI."""
    client = MeridianClient(endpoint="meridian", command=["meridian"])
    calls: list[list[str]] = []

    def fake_run(argv, timeout):
        calls.append(argv)
        if argv[:3] == ["exec", "--json", "sess-1"]:
            return 0, b'{"queued": "task-abc", "session_id": "sess-1"}', b""
        if argv == ["results", "--json"]:
            return 0, json.dumps([{
                "id": "r1",
                "task_id": "task-abc",
                "session_id": "sess-1",
                "module": "builtin/exec",
                "status": "ok",
                "exit_code": 0,
                "ts": 1.0,
                "stdout_b64": "TlQgQVVUSE9SSVRZXFNZU1RFTQ==",  # NT AUTHORITY\SYSTEM
                "stderr_b64": "",
            }]).encode(), b""
        if argv == ["sessions", "--json"]:
            return 0, json.dumps([{
                "id": "sess-1",
                "hostname": "WS01",
                "os": "windows",
                "arch": "amd64",
                "user": "analyst_t1",
                "listener": "http",
                "last_seen": 1700000000,
                "alive": True,
                "ips": ["10.0.0.5"],
            }]).encode(), b""
        return 0, b"[]", b""

    with patch.object(client, "_run_cli", side_effect=fake_run):
        res = client.shell("sess-1", "whoami")
        assert res.return_code == 0
        assert "SYSTEM" in res.stdout
        assert calls[0][:4] == ["exec", "--json", "sess-1", "--"]

        sessions = client.list_sessions()
        assert len(sessions) == 1
        assert sessions[0].hostname == "WS01"
        assert sessions[0].remote_address == "10.0.0.5"

        unsupported = client.execute_assembly("sess-1", "Rubeus.exe")
        assert unsupported.return_code == 2
        assert unsupported.stdout == ""
        assert "no execute-assembly" in unsupported.stderr

        no_psexec = client.psexec("sess-1", "DC01", "svc", "bin.exe")
        assert no_psexec.return_code == 2
        assert "no psexec" in no_psexec.stderr


LIVE_SLIVER_SESSIONS_TABLE = (
    " ID         Name               Transport   Remote Address     Hostname       Username   Process (PID)"
    "         Operating System   Locale   Last Message                             Health  \n"
    "========== ================== =========== ================== ============== ========== ====================="
    "===== ================== ======== ======================================== =========\n"
    " e9716f96   GENETIC_TORTOISE   mtls        172.19.0.4:34404   30dff580990c   root       "
    "/tmp/implant (6349)   linux/amd64                 Sun Aug 30 15:09:05 UTC 2026 (16s ago)"
    "   \x1b[1;38;2;23;201;100m[ALIVE]\x1b[m \n"
    " fd1291ff   GENETIC_TORTOISE   mtls        172.19.0.4:34420   30dff580990c   root       "
    "/tmp/implant (6286)   linux/amd64                 Sun Aug 30 15:09:07 UTC 2026 (14s ago)"
    "   \x1b[1;38;2;23;201;100m[ALIVE]\x1b[m \n"
)


def test_sliver_sessions_table_parser():
    """Parse the fixed-width console table captured live from sliver v1.7.6."""
    from redstrike.c2.sliver import _parse_table, _session_from_row

    rows = _parse_table(LIVE_SLIVER_SESSIONS_TABLE)
    assert len(rows) == 2

    first = _session_from_row(rows[0])
    assert first is not None
    assert first.id == "e9716f96"
    assert first.transport == "mtls"
    assert first.hostname == "30dff580990c"
    assert first.username == "root"
    assert first.os == "linux"
    assert first.arch == "amd64"
    assert first.remote_address == "172.19.0.4:34404"
    assert first.is_alive is True
    assert first.last_seen is not None and first.last_seen.year == 2026


def test_sliver_sessions_table_empty():
    from redstrike.c2.sliver import _parse_table

    assert _parse_table("\x1b[2K\x1b[1;38;2;51;142;247m[*] \x1b[mNo sessions \xf0\x9f\x99\x81\n") == []


def test_sliver_execute_output_block():
    from redstrike.c2.sliver import _output_block

    sample = (
        "\x1b[2K\x1b[1;38;2;51;142;247m[*] \x1b[mExecute: /usr/bin/hostname []\n"
        "\x1b[2K\x1b[2K\x1b[1;38;2;51;142;247m[*] \x1b[mOutput:\n"
        "30dff580990c\n"
    )
    assert _output_block(sample) == "30dff580990c"


def test_sliver_psexec_headless_unsupported():
    client = SliverClient(sliver_binary="/nonexistent/sliver-client")
    res = client.psexec("s1", "DC01", "RedStrikeSvc", "bin.exe")
    assert res.return_code == 2
    assert "interactive" in res.stderr


def test_meridian_client_no_such_session():
    """A rejected exec (`{"error": ...}`) must surface as a failed result."""
    client = MeridianClient(endpoint="meridian", command=["meridian"])

    def fake_run(argv, timeout):
        if argv[:3] == ["exec", "--json", "nope"]:
            return 0, b'{"error": "no such session"}', b""
        return 0, b"[]", b""

    with patch.object(client, "_run_cli", side_effect=fake_run):
        res = client.shell("nope", "whoami")
        assert res.return_code == 1
        assert res.stdout == ""
        assert "no such session" in res.stderr


def test_mythic_client_factory():
    """Verify the C2 factory dispatches Mythic correctly."""
    from redstrike.c2 import get_c2_client
    from redstrike.c2.mythic import MythicClient

    client = get_c2_client(C2Backend.MYTHIC, endpoint="http://127.0.0.1:7443")
    assert isinstance(client, MythicClient)
    assert client.endpoint == "http://127.0.0.1:7443"


def test_mythic_intent_registry():
    """Verify Mythic intents are registered and produce typed CallSpec."""
    registry = IntentRegistry()
    assert "c2.mythic.shell" in registry.known()
    assert "c2.mythic.execute_assembly" in registry.known()
    assert "c2.mythic.psexec" in registry.known()
    assert "c2.mythic.list_sessions" in registry.known()

    spec = registry.build_spec(
        "c2.mythic.execute_assembly",
        {"session_id": "1", "assembly": "Rubeus.exe", "args": ["kerberoast"]},
    )
    assert spec.kind == CallKind.C2
    assert spec.c2_backend == C2Backend.MYTHIC
    assert spec.session_id == "1"
    assert spec.assembly == "Rubeus.exe"


def test_mythic_client_list_sessions():
    """Verify list_sessions parses psql callback rows into C2Session objects."""
    from redstrike.c2.mythic import MythicClient

    client = MythicClient(endpoint="http://127.0.0.1:7443")
    psql_rows = [
        {
            "display_id": "1",
            "host": "WS01",
            "user": "analyst_t1",
            "os": "windows",
            "architecture": "amd64",
            "active": "true",
            "ip": "10.0.0.5",
            "external_ip": "203.0.113.1",
            "process_name": "explorer.exe",
            "description": "initial callback",
            "init_callback": "2026-09-06 12:00:00",
            "last_checkin": "2026-09-06 12:30:00",
        }
    ]
    with patch.object(client, "_psql", return_value=psql_rows):
        sessions = client.list_sessions()
        assert len(sessions) == 1
        s = sessions[0]
        assert s.id == "1"
        assert s.backend == C2Backend.MYTHIC
        assert s.hostname == "WS01"
        assert s.username == "analyst_t1"
        assert s.os == "windows"
        assert s.is_alive is True
        assert s.remote_address == "10.0.0.5"
        assert s.last_seen is not None and s.last_seen.year == 2026


def test_mythic_client_shell_task_flow():
    """Verify shell() creates a task and polls for completion."""
    from redstrike.c2.mythic import MythicClient

    client = MythicClient(endpoint="http://127.0.0.1:7443", api_key="fake-token")

    create_result = {"status": "success", "id": 42}

    with patch.object(client, "_create_task", return_value=create_result), \
         patch.object(client, "_poll_task") as mock_poll:
        mock_poll.return_value = CommandResult(
            command=["mythic", "task", "42"],
            return_code=0,
            stdout="root\n",
            stderr="",
            duration_seconds=0.5,
        )
        res = client.shell("1", "whoami")
        assert res.return_code == 0
        assert "root" in res.stdout
        mock_poll.assert_called_once_with(42, 60)


def test_mythic_client_shell_bad_session_id():
    """Non-integer session IDs are rejected with rc=2."""
    from redstrike.c2.mythic import MythicClient

    client = MythicClient(endpoint="http://127.0.0.1:7443")
    res = client.shell("not-a-number", "whoami")
    assert res.return_code == 2
    assert "integer" in res.stderr


def test_mythic_client_task_creation_failure():
    """When task creation fails, shell() surfaces the error immediately."""
    from redstrike.c2.mythic import MythicClient

    client = MythicClient(endpoint="http://127.0.0.1:7443", api_key="fake")
    with patch.object(client, "_create_task", return_value={"status": "error", "error": "callback not found"}):
        res = client.shell("1", "whoami")
        assert res.return_code == 1
        assert "callback not found" in res.stderr


def test_mythic_client_psexec():
    """psexec creates a task with the right params structure."""
    from redstrike.c2.mythic import MythicClient

    client = MythicClient(endpoint="http://127.0.0.1:7443", api_key="fake")
    create_result = {"status": "success", "id": 99}
    with patch.object(client, "_create_task", return_value=create_result) as mock_create, \
         patch.object(client, "_poll_task") as mock_poll:
        mock_poll.return_value = CommandResult(
            command=["mythic", "task", "99"],
            return_code=0,
            stdout="[+] Service installed",
            stderr="",
            duration_seconds=1.0,
        )
        res = client.psexec("1", "DC01", "svc", "C:\\\\tmp\\\\svc.exe")
        assert res.return_code == 0
        mock_create.assert_called_once()
        call_args = mock_create.call_args[0]
        assert call_args[0] == 1  # callback_id
        assert call_args[1] == "psexec"  # command


def test_orchestrator_dual_mode():
    """Verify CampaignOrchestrator works cleanly in standard mode and in C2 mode."""
    # 1. Standard mode
    orch_std = CampaignOrchestrator(
        engagement_id="test-std",
        beachhead=Beachhead.WINDOWS,
        automation_root=Path("."),
        c2_enabled=False,
    )
    assert orch_std.c2_enabled is False

    # 2. C2-enabled mode
    mock_c2 = MockC2Client()
    orch_c2 = CampaignOrchestrator(
        engagement_id="test-c2",
        beachhead=Beachhead.SESSION,
        automation_root=Path("."),
        c2_enabled=True,
        c2_backend=C2Backend.SLIVER,
        c2_session_id="test-session-uuid-1",
        runner=CommandRunner(c2_client=mock_c2),
    )
    assert orch_c2.c2_enabled is True
    assert orch_c2.c2_session_id == "test-session-uuid-1"
