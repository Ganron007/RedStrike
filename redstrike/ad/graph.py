from __future__ import annotations

import networkx as nx

from redstrike.core.models import EvidenceRecord, Finding, RiskLevel

_RISK_ORDER = {
    RiskLevel.CRITICAL: 5,
    RiskLevel.HIGH: 4,
    RiskLevel.MEDIUM: 3,
    RiskLevel.LOW: 2,
    RiskLevel.INFO: 1,
}

_HIGH_VALUE_ENTITY_KINDS = {"admin_count", "delegation", "adcs"}


class ADKnowledgeGraph:
    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()

    def ingest_evidence(self, evidence: EvidenceRecord) -> None:
        self.graph.add_node(evidence.target, kind="target")
        self.graph.add_node(evidence.technique, kind="technique")
        self.graph.add_edge(
            evidence.target,
            evidence.technique,
            relation="observed",
            evidence_id=evidence.id,
            confidence=evidence.confidence,
        )

    def rank_findings(
        self, findings: list[Finding], evidence: list[EvidenceRecord] | None = None
    ) -> list[Finding]:
        evidence_by_id = {item.id: item for item in (evidence or [])}

        def score(finding: Finding) -> float:
            base = _RISK_ORDER[finding.risk]
            confidence_boost = 0.0
            entity_boost = 0.0
            for evidence_id in finding.evidence_ids:
                record = evidence_by_id.get(evidence_id)
                if record is None:
                    continue
                confidence_boost += record.confidence
                for entity in record.parsed.get("entities", []):
                    if entity.get("kind") in _HIGH_VALUE_ENTITY_KINDS:
                        entity_boost += 0.5
            return base + confidence_boost + entity_boost

        return sorted(findings, key=score, reverse=True)

