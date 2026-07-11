from __future__ import annotations

from cadre_strike.core.models import EvidenceRecord, Finding


def render_markdown_report(findings: list[Finding], evidence: list[EvidenceRecord]) -> str:
    evidence_by_id = {item.id: item for item in evidence}
    lines = [
        "# RedStrike Assessment Report",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append("No findings were generated from the supplied evidence.")
        lines.append("")

    for finding in findings:
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- Risk: `{finding.risk.value}`",
                f"- Target: `{finding.target}`",
                f"- Summary: {finding.summary}",
                "",
                "Evidence:",
            ]
        )
        for evidence_id in finding.evidence_ids:
            record = evidence_by_id.get(evidence_id)
            if not record:
                continue
            lines.extend(
                [
                    f"- `{record.id}` `{record.tool}` `{record.technique}`",
                    f"  Command: `{' '.join(record.command)}`",
                ]
            )
        if finding.remediation:
            lines.append("")
            lines.append("Remediation:")
            for item in finding.remediation:
                lines.append(f"- {item}")
        lines.append("")

    lines.extend(["## Evidence Index", ""])
    for record in evidence:
        lines.extend(
            [
                f"### {record.id}",
                "",
                f"- Time: `{record.observed_at.isoformat()}`",
                f"- Target: `{record.target}`",
                f"- Technique: `{record.technique}`",
                f"- Tool: `{record.tool}`",
                f"- Confidence: `{record.confidence}`",
                "",
            ]
        )

    return "\n".join(lines)

