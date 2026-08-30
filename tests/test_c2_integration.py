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


def test_meridian_client_mock_http():
    """Verify MeridianClient handles REST API requests and responses."""
    client = MeridianClient(endpoint="http://127.0.0.1:8080")

    mock_resp = (200, json.dumps({"output": "NT AUTHORITY\\SYSTEM", "status": "ok"}))
    with patch.object(client, "_http_request", return_value=mock_resp):
        res = client.shell("sess-1", "whoami")
        assert res.return_code == 0
        assert "SYSTEM" in res.stdout


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
