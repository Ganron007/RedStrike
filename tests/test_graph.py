from redstrike.ad.graph import ADKnowledgeGraph
from redstrike.core.models import EvidenceRecord, Finding, RiskLevel


def _evidence(ev_id: str, *, entities: list[dict] | None = None, confidence: float = 0.6) -> EvidenceRecord:
    return EvidenceRecord(
        id=ev_id,
        technique="T1069.002",
        target="10.0.0.1",
        tool="netexec",
        command=["nxc"],
        raw_output="x",
        parsed={"entities": entities or []},
        confidence=confidence,
    )


def test_rank_findings_falls_back_to_risk_without_evidence() -> None:
    low = Finding(id="low", title="low", risk=RiskLevel.LOW, target="10.0.0.1", summary="s")
    high = Finding(id="high", title="high", risk=RiskLevel.HIGH, target="10.0.0.1", summary="s")

    ranked = ADKnowledgeGraph().rank_findings([low, high])
    assert [f.id for f in ranked] == ["high", "low"]


def test_rank_findings_boosts_high_value_entities() -> None:
    ev = _evidence("e1", entities=[{"kind": "admin_count", "name": "ignite\\admin"}], confidence=0.8)
    with_entity = Finding(
        id="with", title="t", risk=RiskLevel.MEDIUM, target="10.0.0.1", summary="s", evidence_ids=["e1"]
    )
    without_entity = Finding(
        id="without", title="t", risk=RiskLevel.MEDIUM, target="10.0.0.1", summary="s", evidence_ids=[]
    )

    ranked = ADKnowledgeGraph().rank_findings([with_entity, without_entity], evidence=[ev])
    assert ranked[0].id == "with"


def test_rank_findings_is_deterministic() -> None:
    ev = _evidence("e1", entities=[{"kind": "delegation", "name": "ignite\\svc"}], confidence=0.9)
    a = Finding(id="a", title="t", risk=RiskLevel.LOW, target="10.0.0.1", summary="s", evidence_ids=["e1"])
    b = Finding(id="b", title="t", risk=RiskLevel.LOW, target="10.0.0.1", summary="s", evidence_ids=[])

    graph = ADKnowledgeGraph()
    first = [f.id for f in graph.rank_findings([a, b], evidence=[ev])]
    second = [f.id for f in graph.rank_findings([b, a], evidence=[ev])]
    assert first == second
    assert first[0] == "a"


def test_ingest_evidence_builds_graph_nodes() -> None:
    graph = ADKnowledgeGraph()
    graph.ingest_evidence(_evidence("e1"))
    assert graph.graph.has_node("10.0.0.1")
    assert graph.graph.has_node("T1069.002")
