from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, SecretStr, field_serializer


class EngagementMode(str, Enum):
    OBSERVE = "observe"
    ASSESS = "assess"
    VALIDATE = "validate"
    REPORT = "report"


class CallKind(str, Enum):
    ARGV = "argv"
    C2 = "c2"
    HTTP = "http"


class C2Backend(str, Enum):
    SLIVER = "sliver"
    MERIDIAN = "meridian"
    MYTHIC = "mythic"


class C2TaskType(str, Enum):
    EXECUTE_ASSEMBLY = "execute_assembly"
    SHELL = "shell"
    PSEXEC = "psexec"
    LIST_SESSIONS = "list_sessions"
    TASK = "task"


class C2Session(BaseModel):
    id: str
    backend: C2Backend
    hostname: str
    username: str
    os: str = "windows"
    arch: str = "amd64"
    transport: str = "http"
    last_seen: datetime | None = None
    is_alive: bool = True
    remote_address: str | None = None


class CallSpec(BaseModel):
    """Execution descriptor for either a direct subprocess or a C2 implant task."""

    kind: CallKind = CallKind.ARGV
    argv: list[str] = Field(default_factory=list)
    c2_backend: C2Backend | None = None
    c2_task_type: C2TaskType | None = None
    session_id: str | None = None
    assembly: str | None = None
    args: list[str] = Field(default_factory=list)
    url: str | None = None
    method: str = "GET"
    body: dict[str, Any] | None = None
    headers: dict[str, str] = Field(default_factory=dict)

    def to_display_command(self) -> list[str]:
        """Convert to a representative command list for display, redaction, and ledgers."""
        if self.kind == CallKind.ARGV:
            return self.argv
        if self.kind == CallKind.C2:
            backend_str = self.c2_backend.value if self.c2_backend else "c2"
            task_str = self.c2_task_type.value if self.c2_task_type else "exec"
            prefix = [f"c2:{backend_str}", task_str]
            if self.session_id:
                prefix.extend(["--session", self.session_id])
            if self.assembly:
                prefix.extend(["--assembly", self.assembly])
            return prefix + self.args
        if self.kind == CallKind.HTTP:
            return ["http", self.method, self.url or ""]
        return self.argv


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OpsecTier(str, Enum):
    STEALTH = "stealth"
    BALANCED = "balanced"
    LOUD = "loud"


class OpsecProfile(BaseModel):
    tier: OpsecTier = OpsecTier.BALANCED
    mitre_attack: list[str] = Field(default_factory=list)
    expected_event_ids: list[int] = Field(default_factory=list)
    noise_score: float = Field(default=0.5, ge=0.0, le=1.0)
    detection_vectors: list[str] = Field(default_factory=list)


class ADRequest(BaseModel):
    target: str = Field(..., description="Domain controller, host, or allowed IP target")
    domain: str | None = Field(default=None, description="AD DNS domain name")
    username: str | None = None
    password: SecretStr | None = None
    nt_hash: SecretStr | None = None
    mode: EngagementMode = EngagementMode.OBSERVE
    kdc_host: str | None = None
    engagement_id: str | None = None
    operator_id: str | None = None
    run_id: str | None = None
    source_system: str | None = None
    evidence_tags: list[str] = Field(default_factory=list)

    @field_serializer("password", "nt_hash")
    def redact_secret(self, value: SecretStr | None) -> str | None:
        return "***REDACTED***" if value else None


class CommandResult(BaseModel):
    command: list[str]
    return_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.return_code == 0 and not self.timed_out


class EvidenceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    technique: str
    target: str
    tool: str
    command: list[str]
    raw_output: str
    parsed: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    opsec: OpsecProfile | None = None
    engagement_id: str | None = None
    operator_id: str | None = None
    run_id: str | None = None
    source_system: str | None = None
    evidence_tags: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    risk: RiskLevel
    target: str
    summary: str
    evidence_ids: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    opsec: OpsecProfile | None = None
    remediation: list[str] = Field(default_factory=list)


class OperationResponse(BaseModel):
    success: bool
    result: CommandResult | None = None
    evidence: EvidenceRecord | None = None
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
    run_id: str | None = None

