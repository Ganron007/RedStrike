from redstrike.core.models import EvidenceRecord, Finding, RiskLevel
from redstrike.reporting.json_report import render_json_report


def test_json_report_includes_required_fields() -> None:
    evidence = EvidenceRecord(
        technique="T1069.002",
        target="10.0.0.1",
        tool="netexec",
        command=["nxc"],
        raw_output="x",
        parsed={"entities": [{"kind": "user", "name": "ignite\\alice"}]},
        confidence=0.8,
    )
    finding = Finding(
        id="f1",
        title="Privileged group membership",
        risk=RiskLevel.HIGH,
        target="10.0.0.1",
        summary="Account in privileged group",
        evidence_ids=[evidence.id],
        mitre_attack=["T1069.002"],
        remediation=["Review group membership"],
    )

    report = render_json_report([finding], [evidence])

    assert report["tool"] == "RedStrike"
    assert report["summary"]["finding_count"] == 1
    assert report["summary"]["evidence_count"] == 1
    assert report["summary"]["risk_breakdown"]["high"] == 1
    assert report["findings"][0]["evidence_ids"] == [evidence.id]
    assert report["findings"][0]["mitre_attack"] == ["T1069.002"]
    assert report["findings"][0]["remediation"] == ["Review group membership"]
    assert report["evidence"][0]["confidence"] == 0.8
    assert report["evidence"][0]["parsed"]["entities"][0]["name"] == "ignite\\alice"
