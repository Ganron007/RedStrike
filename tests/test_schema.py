import pytest
from pydantic import ValidationError

from cadre_strike.core.models import (
    ADRequest,
    EngagementMode,
    EvidenceRecord,
    OperationResponse,
    RiskLevel,
)


def test_adrequest_requires_target() -> None:
    with pytest.raises(ValidationError):
        ADRequest()


def test_adrequest_accepts_and_serializes_metadata_fields() -> None:
    request = ADRequest(
        target="10.0.0.1",
        engagement_id="eng-1",
        operator_id="op-1",
        run_id="run-1",
        source_system="cadre",
        evidence_tags=["adcs", "phase1"],
    )
    dumped = request.model_dump()
    assert dumped["engagement_id"] == "eng-1"
    assert dumped["operator_id"] == "op-1"
    assert dumped["run_id"] == "run-1"
    assert dumped["source_system"] == "cadre"
    assert dumped["evidence_tags"] == ["adcs", "phase1"]


def test_adrequest_mode_coerces_string() -> None:
    request = ADRequest(target="10.0.0.1", mode="assess")
    assert request.mode == EngagementMode.ASSESS


def test_adrequest_redacts_secret_on_dump() -> None:
    request = ADRequest(target="10.0.0.1", password="hunter2")
    dumped = request.model_dump()
    assert dumped["password"] == "***REDACTED***"


def test_operation_response_round_trips() -> None:
    response = OperationResponse(success=True, run_id="run-1")
    restored = OperationResponse.model_validate(response.model_dump())
    assert restored.success is True
    assert restored.run_id == "run-1"


def test_evidence_record_serializes_parsed_entities() -> None:
    evidence = EvidenceRecord(
        technique="T1069.002",
        target="10.0.0.1",
        tool="netexec",
        command=["nxc"],
        raw_output="x",
        parsed={"entities": [{"kind": "user", "name": "ignite\\alice"}]},
        confidence=0.5,
    )
    dumped = evidence.model_dump()
    assert dumped["parsed"]["entities"][0]["kind"] == "user"
    restored = EvidenceRecord.model_validate(dumped)
    assert restored.parsed["entities"][0]["name"] == "ignite\\alice"


def test_finding_model_includes_attack_and_remediation() -> None:
    from cadre_strike.core.models import Finding

    finding = Finding(
        id="f1",
        title="t",
        risk=RiskLevel.HIGH,
        target="10.0.0.1",
        summary="s",
        evidence_ids=["e1"],
        mitre_attack=["T1069.002"],
        remediation=["review"],
    )
    dumped = finding.model_dump()
    assert dumped["mitre_attack"] == ["T1069.002"]
    assert dumped["remediation"] == ["review"]
    assert dumped["risk"] == "high"
