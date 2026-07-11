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


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Credential(BaseModel):
    domain: str | None = None
    username: str
    password: SecretStr | None = None
    nt_hash: SecretStr | None = None

    @field_serializer("password", "nt_hash")
    def redact_secret(self, value: SecretStr | None) -> str | None:
        return "***REDACTED***" if value else None


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
    remediation: list[str] = Field(default_factory=list)


class OperationResponse(BaseModel):
    success: bool
    result: CommandResult | None = None
    evidence: EvidenceRecord | None = None
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
    run_id: str | None = None

