import threading

import pytest

from redstrike.ad.service import ActiveDirectoryAssessmentService
from redstrike.core.errors import GuardrailViolationError
from redstrike.core.models import ADRequest, CommandResult
from redstrike.core.policy import ScopePolicy


class FakeRunner:
    def __init__(self, stdout: str = "Lockout threshold: None\n") -> None:
        self.argv: list[str] | None = None
        self.stdout = stdout

    def run(self, argv: list[str]) -> CommandResult:
        self.argv = argv
        return CommandResult(
            command=argv,
            return_code=0,
            stdout=self.stdout,
            stderr="",
            duration_seconds=0.01,
        )


def test_password_policy_generates_spray_risk_finding() -> None:
    runner = FakeRunner()
    service = ActiveDirectoryAssessmentService(ScopePolicy(), runner=runner)  # type: ignore[arg-type]

    response = service.password_policy(
        ADRequest(target="192.168.1.7", domain="ignite.local", username="raaz")
    )

    assert response.success
    assert response.findings
    assert response.findings[0].title == "Domain password policy has no lockout threshold"
    assert runner.argv == [
        "nxc",
        "smb",
        "192.168.1.7",
        "-u",
        "raaz",
        "-d",
        "ignite.local",
        "--pass-pol",
    ]


def test_adcs_enum_runs_read_only_ldap_operation() -> None:
    runner = FakeRunner()
    service = ActiveDirectoryAssessmentService(ScopePolicy(), runner=runner)  # type: ignore[arg-type]

    response = service.adcs_enum(
        ADRequest(
            target="192.168.1.7",
            domain="ignite.local",
            username="raaz",
            engagement_id="eng-001",
            operator_id="op-1",
            run_id="run-001",
            source_system="redstrike",
            evidence_tags=["adcs", "phase1"],
        )
    )

    assert response.success
    assert response.evidence
    assert response.evidence.technique == "T1649"
    assert response.run_id == "run-001"
    assert response.evidence.engagement_id == "eng-001"
    assert response.evidence.operator_id == "op-1"
    assert response.evidence.run_id == "run-001"
    assert response.evidence.source_system == "redstrike"
    assert response.evidence.evidence_tags == ["adcs", "phase1"]
    assert runner.argv == [
        "nxc",
        "ldap",
        "192.168.1.7",
        "-u",
        "raaz",
        "-d",
        "ignite.local",
        "--adcs",
    ]


ADCS_SAMPLE = (
    "LDAP 192.168.1.7 389 ignite.local [*] Total templates: 2\n"
    "LDAP 192.168.1.7 389 ignite.local - ESC1 (Enrollment Agent)\n"
    "LDAP 192.168.1.7 389 ignite.local - ESC2 (...) \n"
)


def test_adcs_enum_normalizes_parsed_entities_into_evidence() -> None:
    runner = FakeRunner(stdout=ADCS_SAMPLE)
    service = ActiveDirectoryAssessmentService(ScopePolicy(), runner=runner)  # type: ignore[arg-type]

    response = service.adcs_enum(
        ADRequest(target="192.168.1.7", domain="ignite.local", username="raaz")
    )

    assert response.success
    assert response.evidence
    entities = response.evidence.parsed["entities"]
    assert entities
    assert entities[0]["kind"] == "adcs"
    assert entities[0]["name"] == "ESC1"
    assert entities[1]["name"] == "ESC2"


def test_service_blocks_concurrent_runs_for_same_target() -> None:
    class BlockingRunner:
        def __init__(self) -> None:
            self.entered = threading.Event()
            self.release = threading.Event()

        def run(self, argv: list[str]) -> CommandResult:
            self.entered.set()
            self.release.wait(timeout=2)
            return CommandResult(
                command=argv,
                return_code=0,
                stdout="ok\n",
                stderr="",
                duration_seconds=0.01,
            )

    runner = BlockingRunner()
    policy = ScopePolicy(max_concurrent_per_target=1, max_concurrent_per_domain=5)
    service = ActiveDirectoryAssessmentService(policy, runner=runner)  # type: ignore[arg-type]
    request = ADRequest(target="192.168.1.7", domain="ignite.local", username="raaz")

    first_done = threading.Event()

    def first_call() -> None:
        try:
            service.domain_users(request)
        finally:
            first_done.set()

    thread = threading.Thread(target=first_call)
    thread.start()
    assert runner.entered.wait(timeout=2)

    with pytest.raises(GuardrailViolationError, match="exceeded max concurrent"):
        service.domain_users(request)

    runner.release.set()
    assert first_done.wait(timeout=2)
    thread.join(timeout=2)


def test_service_enforces_target_cooldown() -> None:
    tick = [100.0]

    def fake_clock() -> float:
        return tick[0]

    runner = FakeRunner()
    policy = ScopePolicy(cooldown_seconds_per_target=5.0)
    service = ActiveDirectoryAssessmentService(  # type: ignore[arg-type]
        policy,
        runner=runner,
        monotonic_clock=fake_clock,
    )
    request = ADRequest(target="192.168.1.7", domain="ignite.local", username="raaz")

    first = service.domain_users(request)
    assert first.success

    tick[0] = 102.0
    with pytest.raises(GuardrailViolationError, match="Target '192.168.1.7' is in cooldown"):
        service.domain_users(request)

    tick[0] = 106.0
    second = service.domain_users(request)
    assert second.success
