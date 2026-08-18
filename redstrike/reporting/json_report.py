from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from redstrike.core.models import EvidenceRecord, Finding


def render_json_report(findings: list[Finding], evidence: list[EvidenceRecord]) -> dict:
    risk_breakdown: Counter[str] = Counter()
    for finding in findings:
        risk_breakdown[finding.risk.value] += 1

    return {
        "tool": "RedStrike",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "finding_count": len(findings),
            "evidence_count": len(evidence),
            "risk_breakdown": dict(risk_breakdown),
        },
        "findings": [finding.model_dump(mode="json") for finding in findings],
        "evidence": [record.model_dump(mode="json") for record in evidence],
    }
