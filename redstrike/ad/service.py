from __future__ import annotations

import threading
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from tempfile import gettempdir

from redstrike.ad.netexec import NetExecCommandBuilder
from redstrike.ad.parsers import parse_for_action
from redstrike.core.errors import GuardrailViolationError
from redstrike.core.models import ADRequest, EvidenceRecord, Finding, OperationResponse, RiskLevel
from redstrike.core.policy import ScopePolicy
from redstrike.core.runner import CommandRunner


class ActiveDirectoryAssessmentService:
    def __init__(
        self,
        policy: ScopePolicy,
        runner: CommandRunner | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ):
        self.policy = policy
        self.runner = runner or CommandRunner()
        self.builder = NetExecCommandBuilder()
        self._clock = monotonic_clock or time.monotonic
        self._lock = threading.Lock()
        self._active_by_target: dict[str, int] = defaultdict(int)
        self._active_by_domain: dict[str, int] = defaultdict(int)
        self._last_finish_by_target: dict[str, float] = {}
        self._last_finish_by_domain: dict[str, float] = {}

    def domain_users(self, request: ADRequest) -> OperationResponse:
        return self._run("domain_users", "T1087.002", request, self.builder.users)

    def domain_groups(self, request: ADRequest) -> OperationResponse:
        return self._run("domain_groups", "T1069.002", request, self.builder.groups)

    def domain_computers(self, request: ADRequest) -> OperationResponse:
        return self._run("domain_computers", "T1018", request, self.builder.computers)

    def password_policy(self, request: ADRequest) -> OperationResponse:
        response = self._run("password_policy", "T1201", request, self.builder.password_policy)
        if response.evidence and "Lockout threshold: None" in response.evidence.raw_output:
            response.findings.append(
                Finding(
                    title="Domain password policy has no lockout threshold",
                    risk=RiskLevel.HIGH,
                    target=request.target,
                    summary="No lockout threshold materially increases password spraying risk.",
                    evidence_ids=[response.evidence.id],
                    mitre_attack=["T1110.003"],
                    remediation=[
                        "Set an account lockout threshold aligned with business tolerance.",
                        "Monitor failed authentication patterns across the domain.",
                    ],
                )
            )
        return response

    def shares(self, request: ADRequest) -> OperationResponse:
        return self._run("shares", "T1135", request, self.builder.shares)

    def asrep_roastable(self, request: ADRequest) -> OperationResponse:
        output_file = str(Path(gettempdir()) / f"redstrike_asrep_{request.target.replace('.', '_')}.txt")
        return self._run(
            "asrep_roastable",
            "T1558.004",
            request,
            lambda **kwargs: self.builder.asrep_roastable(output_file, **kwargs),
        )

    def kerberoastable(self, request: ADRequest) -> OperationResponse:
        output_file = str(Path(gettempdir()) / f"redstrike_kerberoast_{request.target.replace('.', '_')}.txt")
        return self._run(
            "kerberoastable",
            "T1558.003",
            request,
            lambda **kwargs: self.builder.kerberoastable(output_file, **kwargs),
        )

    def delegation(self, request: ADRequest) -> OperationResponse:
        return self._run("delegation", "T1558", request, self.builder.delegation)

    def admin_count(self, request: ADRequest) -> OperationResponse:
        return self._run("admin_count", "T1069.002", request, self.builder.admin_count)

    def adcs_enum(self, request: ADRequest) -> OperationResponse:
        return self._run("adcs_enum", "T1649", request, self.builder.adcs_enum)

    def _run(self, action: str, technique: str, request: ADRequest, build_command) -> OperationResponse:
        self.policy.assert_allowed(action=action, target=request.target, domain=request.domain, mode=request.mode)
        domain_key = request.domain.lower() if request.domain else None
        self._acquire_guardrails(request.target, domain_key)
        try:
            argv = build_command(
                target=request.target,
                username=request.username,
                password=request.password,
                nt_hash=request.nt_hash,
                domain=request.domain,
                kdc_host=request.kdc_host,
            )
            result = self.runner.run(argv)
            entities = parse_for_action(action, result.stdout)
            evidence = EvidenceRecord(
                technique=technique,
                target=request.target,
                tool="netexec",
                command=result.command,
                raw_output=result.stdout,
                parsed={
                    "stderr": result.stderr,
                    "return_code": result.return_code,
                    "entities": [entity.model_dump() for entity in entities],
                },
                confidence=0.7 if result.success else 0.3,
                engagement_id=request.engagement_id,
                operator_id=request.operator_id,
                run_id=request.run_id,
                source_system=request.source_system,
                evidence_tags=request.evidence_tags,
            )
            return OperationResponse(success=result.success, result=result, evidence=evidence, run_id=request.run_id)
        finally:
            self._release_guardrails(request.target, domain_key)

    def _acquire_guardrails(self, target: str, domain_key: str | None) -> None:
        now = self._clock()
        with self._lock:
            target_active = self._active_by_target[target]
            if target_active >= self.policy.max_concurrent_per_target:
                raise GuardrailViolationError(
                    f"Target '{target}' exceeded max concurrent runs ({self.policy.max_concurrent_per_target})"
                )

            if domain_key:
                domain_active = self._active_by_domain[domain_key]
                if domain_active >= self.policy.max_concurrent_per_domain:
                    raise GuardrailViolationError(
                        f"Domain '{domain_key}' exceeded max concurrent runs ({self.policy.max_concurrent_per_domain})"
                    )

            target_last = self._last_finish_by_target.get(target)
            if target_last is not None and self.policy.cooldown_seconds_per_target > 0:
                since = now - target_last
                if since < self.policy.cooldown_seconds_per_target:
                    wait = self.policy.cooldown_seconds_per_target - since
                    raise GuardrailViolationError(
                        f"Target '{target}' is in cooldown for another {wait:.2f}s"
                    )

            if domain_key:
                domain_last = self._last_finish_by_domain.get(domain_key)
                if domain_last is not None and self.policy.cooldown_seconds_per_domain > 0:
                    since = now - domain_last
                    if since < self.policy.cooldown_seconds_per_domain:
                        wait = self.policy.cooldown_seconds_per_domain - since
                        raise GuardrailViolationError(
                            f"Domain '{domain_key}' is in cooldown for another {wait:.2f}s"
                        )

            self._active_by_target[target] += 1
            if domain_key:
                self._active_by_domain[domain_key] += 1

    def _release_guardrails(self, target: str, domain_key: str | None) -> None:
        now = self._clock()
        with self._lock:
            target_active = max(0, self._active_by_target.get(target, 0) - 1)
            if target_active == 0:
                self._active_by_target.pop(target, None)
            else:
                self._active_by_target[target] = target_active
            self._last_finish_by_target[target] = now

            if domain_key:
                domain_active = max(0, self._active_by_domain.get(domain_key, 0) - 1)
                if domain_active == 0:
                    self._active_by_domain.pop(domain_key, None)
                else:
                    self._active_by_domain[domain_key] = domain_active
                self._last_finish_by_domain[domain_key] = now
