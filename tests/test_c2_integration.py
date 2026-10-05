from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

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
from redstrike.runtime.windows_transport import argv_for_plan


class MockC2Client(BaseC2Client):
    """Test double for C2 backends."""

    def __init__(self, backend: C2Backend = C2Backend.SLIVER):
        self.backend = backend
        self.sessions = [
            C2Session(
                id="test-session-uuid-1",
                backend=backend,
                hostname="win-target",
                username="operator",
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
            stdout="whoami -> child\\operator",
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
        declared_path="windows",
        beachhead=Beachhead.SESSION,
    )
    assert path == ExecutionPath.C2_IMPLANT


def test_windows_transport_c2_plan():
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
        uses_windows_exec=False,
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
                "hostname": "win-target",
                "os": "windows",
                "arch": "amd64",
                "user": "operator",
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
        assert sessions[0].hostname == "win-target"
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
    """Parse the fixed-width console table captured live from sliver v1.7.6
    (format re-verified verbatim on v1.7.7, 2026-10-04)."""
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


# Verbatim capture from sliver v1.7.7 (`console --rc` with sessions + beacons):
# two tables with DIFFERENT column widths — the beacons table adds
# Tasks/Next Check-In columns, and slicing its rows with the sessions header
# yields garbage fields (the bug this fixture guards).
LIVE_SLIVER_TWO_TABLES = (
    " ID         Name                Transport   Remote Address                      Hostname   Username       Process (PID)"
    "                                Integrity   Operating System   Locale   Last Message                                Health\n"
    "========== =================== =========== =================================== ========== ============== ============================================"
    " =========== ================== ======== =========================================== ========\n"
    " a5d9dc29   PREVIOUS_INTEREST   http(s)     tcp(172.19.0.3:49546)->172.19.0.1   tgt1       TGT1\\manager   "
    "C:\\Users\\manager\\Downloads\\slvs.exe (7280)   -           windows/amd64      en-GB    Sun Oct  4 03:01:07 UTC 2026 (47m52s ago)   [DEAD]\n"
    " f5eab021   PREVIOUS_INTEREST   http(s)     tcp(172.19.0.3:49564)->172.19.0.1   tgt1       TGT1\\manager   "
    "C:\\Users\\manager\\Downloads\\slvs.exe (3460)   -           windows/amd64      en-GB    Sun Oct  4 03:01:07 UTC 2026 (47m52s ago)   [DEAD]\n"
    " ID         Name               Tasks   Transport   Remote Address                      Hostname   Username"
    "           Process (PID)                                                   Integrity   Operating System   Locale   Last Check-In"
    "                                   Next Check-In\n"
    "========== ================== ======= =========== =================================== ========== =================="
    " =============================================================== =========== ================== ======== ==============================================="
    " ===============================================\n"
    " 961b4851   STRONG_PEAR        0/2     http(s)     172.19.0.1:35284                    tgt1       TESTLAB\\operator   "
    "C:\\Users\\operator01\\Downloads\\implant-direct-final.exe (1192)   -           windows/amd64      en-GB    "
    "Fri Sep  4 07:15:19 UTC 2026 (716h33m40s ago)   Fri Sep  4 07:16:26 UTC 2026 (716h32m33s ago)\n"
    " 4cabf88a   AWAKE_RICE         0/1     http(s)     tcp(172.19.0.2:44778)->172.19.0.1   tgt1       TESTLAB\\operator   "
    "C:\\Users\\operator01\\Downloads\\implant-v2-final.exe (10720)      -           windows/amd64      en-GB    "
    "Fri Sep  4 08:29:28 UTC 2026 (715h19m31s ago)   Fri Sep  4 08:30:48 UTC 2026 (715h18m11s ago)\n"
)


def test_sliver_two_table_parse_uses_each_header():
    """Sessions AND beacons tables each parse with their own column layout."""
    from redstrike.c2.sliver import _parse_tables, _session_from_row

    tables = _parse_tables(LIVE_SLIVER_TWO_TABLES)
    assert len(tables) == 2
    session_rows = tables[0][1]
    beacon_rows = tables[1][1]
    assert "Health" in tables[0][0]
    assert "Next Check-In" in tables[1][0]
    assert len(session_rows) == 2
    assert len(beacon_rows) == 2

    dead = _session_from_row(session_rows[0])
    assert dead.id == "a5d9dc29"
    assert dead.hostname == "tgt1"
    assert dead.username == "TGT1\\manager"
    assert dead.os == "windows" and dead.arch == "amd64"
    assert dead.transport == "http(s)"
    assert dead.remote_address == "tcp(172.19.0.3:49546)->172.19.0.1"
    assert dead.is_alive is False  # [DEAD] health

    beacon = _session_from_row(beacon_rows[0])
    assert beacon.id == "961b4851"
    assert beacon.hostname == "tgt1"
    assert beacon.username == "TESTLAB\\operator"
    assert beacon.os == "windows"
    assert beacon.transport == "http(s)"
    assert beacon.remote_address == "172.19.0.1:35284"
    assert beacon.is_alive is True  # beacons have no Health column


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


def test_meridian_client_endpoint_with_spaces_splits_argv():
    """An endpoint containing spaces (the CLI `docker exec ...` form) is split
    into an argv vector, not passed as one broken element."""
    client = MeridianClient(endpoint="docker exec -i c2stack-meridian-1 meridian")
    assert client.command == ["docker", "exec", "-i", "c2stack-meridian-1", "meridian"]
    assert MeridianClient(endpoint="meridian").command == ["meridian"]


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
            "id": "1",
            "host": "win-target",
            "user": "operator",
            "os": "windows",
            "architecture": "amd64",
            "active": "true",
            "ip": "[\"10.0.0.5\", \"fe80::aa6e:6876:5bbe:b3ad%11\"]",
            "external_ip": "203.0.113.1",
            "process_name": "explorer.exe",
            "description": "initial callback",
            "init_callback": "2026-09-06 12:00:00",
            "last_checkin": "2026-09-06 12:30:00",
        }
    ]
    with patch.object(client, "_psql", return_value=psql_rows) as mock_psql:
        sessions = client.list_sessions()
        assert "SELECT id, host" in mock_psql.call_args[0][0]
        assert len(sessions) == 1
        s = sessions[0]
        assert s.id == "1"
        assert s.backend == C2Backend.MYTHIC
        assert s.hostname == "win-target"
        assert s.username == "operator"
        assert s.os == "windows"
        assert s.is_alive is True
        assert s.remote_address == "10.0.0.5"
        assert s.last_seen is not None and s.last_seen.year == 2026


def test_mythic_client_shell_task_flow():
    """Verify shell() creates a task and polls for completion."""
    from redstrike.c2.mythic import MythicClient

    client = MythicClient(endpoint="http://127.0.0.1:7443", api_key="fake-token")

    create_result = {"status": "success", "id": 42}

    with patch.object(client, "_create_task", return_value=create_result) as mock_create, \
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
        # `shell` is an ALIAS command: params is the RAW command line, not JSON
        assert mock_create.call_args[0] == (1, "shell", "whoami")


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
    """psexec is rejected with a diagnostic: Apollo has no psexec command."""
    from redstrike.c2.mythic import MythicClient

    client = MythicClient(endpoint="http://127.0.0.1:7443", api_key="fake")
    with patch.object(client, "_create_task") as mock_create:
        res = client.psexec("1", "DC01", "svc", "C:\\\\tmp\\\\svc.exe")
        assert res.return_code == 2
        assert "jump_psexec" in res.stderr
        mock_create.assert_not_called()


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


# ---------------------------------------------------------------------------
# C2Stack Flight Control portal backends (Havoc / Adaptix) — Phase 8.5
# ---------------------------------------------------------------------------

def test_portal_factory_dispatch():
    """havoc/adaptix map to PortalClient with portal endpoints."""
    from redstrike.c2 import get_c2_client
    from redstrike.c2.portal import PortalClient

    havoc = get_c2_client(C2Backend.HAVOC, endpoint="http://127.0.0.1:8000")
    adaptix = get_c2_client("adaptix", endpoint="http://portal.lab:8000")
    assert isinstance(havoc, PortalClient)
    assert havoc.backend == C2Backend.HAVOC
    assert havoc.endpoint == "http://127.0.0.1:8000"
    assert isinstance(adaptix, PortalClient)
    assert adaptix.backend == C2Backend.ADAPTIX
    assert adaptix.endpoint == "http://portal.lab:8000"


def test_portal_rejects_non_portal_backends():
    """PortalClient only drives the frameworks without direct operator APIs."""
    from redstrike.c2.portal import PortalClient

    with pytest.raises(ValueError):
        PortalClient(backend=C2Backend.SLIVER)
    with pytest.raises(ValueError):
        PortalClient(backend=C2Backend.MYTHIC)


def _portal_sessions_payload() -> dict:
    return {
        "count": 3,
        "sessions": [
            {
                "id": "4555ab0e", "backend": "havoc", "hostname": "win-target",
                "username": "operator", "os": "Windows 10", "pid": "5272",
                "is_alive": True, "process": "demon.x64.exe", "listener": "null",
            },
            {
                "id": "52804c91", "backend": "adaptix", "hostname": "win-target",
                "username": "operator", "os": "Win 11 x64", "pid": "5256",
                "is_alive": True, "internal_ip": "198.51.100.62",
                "listener": "cadre_http",
            },
            {
                "id": "23", "backend": "mythic", "hostname": "win-target",
                "username": "operator", "os": "Windows 10 x64",
                "is_alive": True,
            },
        ],
        "backends": {
            "havoc": {"ok": True, "count": 1},
            "adaptix": {"ok": True, "count": 1},
            "mythic": {"ok": True, "count": 1},
        },
    }


def test_portal_list_sessions_filters_and_maps():
    """list_sessions keeps only the requested backend and maps portal fields."""
    from redstrike.c2.portal import PortalClient

    havoc = PortalClient(backend=C2Backend.HAVOC, endpoint="http://portal:8000")
    with patch.object(havoc, "_get_json", return_value=_portal_sessions_payload()):
        sessions = havoc.list_sessions()
        assert len(sessions) == 1
        s = sessions[0]
        assert s.id == "4555ab0e"
        assert s.backend == C2Backend.HAVOC
        assert s.hostname == "win-target"
        assert s.username == "operator"
        assert s.os == "Windows 10"
        assert s.is_alive is True

    adaptix = PortalClient(backend=C2Backend.ADAPTIX, endpoint="http://portal:8000")
    with patch.object(adaptix, "_get_json", return_value=_portal_sessions_payload()):
        sessions = adaptix.list_sessions()
        assert len(sessions) == 1
        assert sessions[0].id == "52804c91"
        assert sessions[0].remote_address == "198.51.100.62"


def test_portal_list_sessions_backend_error():
    """A backend reporting its own error maps to no sessions (honest reporting)."""
    from redstrike.c2.portal import PortalClient

    client = PortalClient(backend=C2Backend.HAVOC, endpoint="http://portal:8000")
    payload = {"count": 0, "sessions": [], "backends": {"havoc": {"ok": False, "error": "ws down"}}}
    with patch.object(client, "_get_json", return_value=payload):
        assert client.list_sessions() == []
    with patch.object(client, "_get_json", return_value=None):
        assert client.list_sessions() == []


def test_portal_havoc_shell_output():
    """Havoc tasking returns the portal-collected output in the same call."""
    from redstrike.c2.portal import PortalClient

    client = PortalClient(backend=C2Backend.HAVOC, endpoint="http://portal:8000")
    response = {
        "ok": True, "backend": "havoc",
        "result": {"task_id": "abc123", "output": "WIN-TARGET\\admin", "errors": ""},
    }
    with patch.object(client, "_post_json", return_value=response) as mock_post:
        res = client.shell("4555ab0e", "whoami")
        assert res.return_code == 0
        assert res.stdout == "WIN-TARGET\\admin"
        assert mock_post.call_args[0][0] == "/api/ops/task"
        assert mock_post.call_args[0][1] == {
            "session_id": "4555ab0e",
            "backend": "havoc",
            "command": "whoami",
            "wait": 25,
        }


def test_portal_havoc_shell_error_output():
    """Havoc errors with no output surface as a failed result."""
    from redstrike.c2.portal import PortalClient

    client = PortalClient(backend=C2Backend.HAVOC, endpoint="http://portal:8000")
    response = {
        "ok": True, "backend": "havoc",
        "result": {"task_id": "abc123", "output": "", "errors": "command rejected"},
    }
    with patch.object(client, "_post_json", return_value=response):
        res = client.shell("4555ab0e", "bogus-command")
        assert res.return_code == 1
        assert "command rejected" in res.stderr


def test_portal_havoc_execute_assembly_uses_dotnet():
    """Havoc in-memory .NET execution tasks the portal `dotnet` command."""
    from redstrike.c2.portal import PortalClient

    client = PortalClient(backend=C2Backend.HAVOC, endpoint="http://portal:8000")
    response = {
        "ok": True, "backend": "havoc",
        "result": {"task_id": "abc", "output": "cadre-assembly-ok", "errors": ""},
    }
    with patch.object(client, "_post_json", return_value=response) as mock_post:
        res = client.execute_assembly("4555ab0e", "/tmp/Rubeus.exe", args=["kerberoast"])
        assert res.return_code == 0
        assert "cadre-assembly-ok" in res.stdout
        assert mock_post.call_args[0][1]["command"] == "dotnet /tmp/Rubeus.exe kerberoast"


def test_portal_adaptix_execute_assembly_rejected():
    """Adaptix AxScript has no assembly loader -> honest rejection."""
    from redstrike.c2.portal import PortalClient

    client = PortalClient(backend=C2Backend.ADAPTIX, endpoint="http://portal:8000")
    res = client.execute_assembly("52804c91", "Rubeus.exe")
    assert res.return_code == 2
    assert "bof" in res.stderr


def test_portal_adaptix_shell_polls_completed_tasks():
    """Adaptix queues via /api/ops/task then polls the completed task list."""
    from redstrike.c2.portal import PortalClient

    client = PortalClient(backend=C2Backend.ADAPTIX, endpoint="http://portal:8000")
    with patch.object(client, "_adaptix_task_ids", return_value={"old1"}), \
         patch.object(client, "_post_json", return_value={"ok": True}) as mock_post, \
         patch.object(client, "_adaptix_tasks", return_value=[
             {"a_task_id": "old1", "a_text": "stale output"},
             {"a_task_id": "new9", "a_text": "NT AUTHORITY\\SYSTEM"},
         ]), \
         patch("redstrike.c2.portal.time.sleep"):
        res = client.shell("52804c91", "shell whoami")
        assert res.return_code == 0
        assert "NT AUTHORITY\\SYSTEM" in res.stdout
        assert mock_post.call_args[0][1] == {
            "session_id": "52804c91",
            "backend": "adaptix",
            "command": "shell whoami",
        }


def test_portal_adaptix_shell_timeout():
    """No new completed adaptix task within the window -> timed_out result."""
    from redstrike.c2.portal import PortalClient

    client = PortalClient(backend=C2Backend.ADAPTIX, endpoint="http://portal:8000", timeout_seconds=60)
    with patch.object(client, "_adaptix_task_ids", return_value=set()), \
         patch.object(client, "_post_json", return_value={"ok": True}), \
         patch.object(client, "_adaptix_tasks", return_value=[]), \
         patch("redstrike.c2.portal.time.sleep"):
        res = client.shell("52804c91", "shell whoami", timeout_seconds=1)
        assert res.return_code == 124
        assert res.timed_out is True


def test_portal_psexec_rejected():
    """Portal backends have no psexec task; shell-based movement is suggested."""
    from redstrike.c2.portal import PortalClient

    client = PortalClient(backend=C2Backend.HAVOC, endpoint="http://portal:8000")
    res = client.psexec("4555ab0e", "DC01", "svc", "C:\\tmp\\svc.exe")
    assert res.return_code == 2
    assert "shell" in res.stderr


def test_portal_intents_registered():
    registry = IntentRegistry()
    assert "c2.havoc.shell" in registry.known()
    assert "c2.havoc.execute_assembly" in registry.known()
    assert "c2.havoc.list_sessions" in registry.known()
    assert "c2.adaptix.shell" in registry.known()
    assert "c2.adaptix.list_sessions" in registry.known()

    spec = registry.build_spec(
        "c2.havoc.shell", {"session_id": "4555ab0e", "command": "whoami"}
    )
    assert spec.kind == CallKind.C2
    assert spec.c2_backend == C2Backend.HAVOC
    assert spec.c2_task_type == C2TaskType.SHELL
    assert spec.session_id == "4555ab0e"
    assert spec.args == ["whoami"]

    spec = registry.build_spec(
        "c2.havoc.execute_assembly",
        {"session_id": "4555ab0e", "assembly": "/tmp/Rubeus.exe", "args": ["kerberoast"]},
    )
    assert spec.c2_backend == C2Backend.HAVOC
    assert spec.c2_task_type == C2TaskType.EXECUTE_ASSEMBLY
    assert spec.assembly == "/tmp/Rubeus.exe"

    spec = registry.build_spec("c2.adaptix.list_sessions", {})
    assert spec.c2_backend == C2Backend.ADAPTIX
    assert spec.c2_task_type == C2TaskType.LIST_SESSIONS


def test_mythic_execute_assembly_uploads_file(tmp_path):
    """execute_assembly stages the assembly, then tasks the uploaded-file group."""
    from redstrike.c2.mythic import MythicClient

    assembly = tmp_path / "Rubeus.exe"
    assembly.write_bytes(b"MZ-fake")
    client = MythicClient(endpoint="http://127.0.0.1:7443", api_key="fake")
    with patch.object(client, "_upload_file", return_value="abc-123") as mock_upload, \
         patch.object(client, "_create_task", return_value={"status": "success", "id": 7}) as mock_create, \
         patch.object(client, "_poll_task") as mock_poll:
        mock_poll.return_value = CommandResult(
            command=["mythic", "task", "7"],
            return_code=0,
            stdout="cadre-assembly-ok",
            stderr="",
            duration_seconds=0.1,
        )
        res = client.execute_assembly("1", str(assembly), args=["kerberoast"])
        assert res.return_code == 0
        assert "cadre-assembly-ok" in res.stdout
        mock_upload.assert_called_once_with("Rubeus.exe", b"MZ-fake")
        params = json.loads(mock_create.call_args[0][2])
        assert params["assembly_file"] == "abc-123"
        assert params["parameter_group_name"] == "New Assembly"
        assert params["parameters"] == "kerberoast"


def test_mythic_execute_assembly_requires_assembly():
    """Missing or unreadable assembly paths are rejected before any tasking."""
    from redstrike.c2.mythic import MythicClient

    client = MythicClient(endpoint="http://127.0.0.1:7443", api_key="fake")
    res = client.execute_assembly("1", "")
    assert res.return_code == 2
    assert "no assembly path" in res.stderr
    res = client.execute_assembly("1", "Z:\\does\\not\\exist.exe")
    assert res.return_code == 2
    assert "cannot read assembly" in res.stderr
