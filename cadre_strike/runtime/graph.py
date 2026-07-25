from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

KNOWN_BRANCHES = frozenset({"spine", "A", "B", "C", "D", "E", "F", "G", "sql-ai"})

# Standalone exercise streams (Plan 1.1 M5) — not on the AD spine.
STREAM_SPECS: dict[str, dict[str, str]] = {
    "E": {"branch": "E", "phase": "9", "beachhead": "linux"},
    "F": {"branch": "F", "phase": "10", "beachhead": "linux"},
}


@dataclass(frozen=True)
class CampaignNode:
    id: str
    phase: float
    title: str
    path: str
    beachheads: tuple[str, ...]
    script: str
    requires_cred: str | None
    produces_cred: str | None
    hitl_gate: str | None = None
    stub: bool = False
    branch: str = "spine"
    intent: str | None = None
    intent_args: dict[str, Any] | None = None
    cred: str | None = None  # ledger name merged into intent args


@dataclass(frozen=True)
class CampaignGraph:
    version: int
    name: str
    nodes: tuple[CampaignNode, ...]

    def nodes_for_phases(self, match: Callable[[float], bool]) -> list[CampaignNode]:
        return [node for node in self.nodes if match(node.phase)]


def load_campaign_graph(path: Path | str) -> CampaignGraph:
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("campaign graph must be a mapping")
    raw_nodes = data.get("nodes")
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise ValueError("campaign graph requires a non-empty nodes list")

    nodes: list[CampaignNode] = []
    for index, item in enumerate(raw_nodes):
        if not isinstance(item, dict):
            raise ValueError(f"nodes[{index}] must be a mapping")
        nodes.append(_parse_node(item, index))

    return CampaignGraph(
        version=int(data.get("version") or 1),
        name=str(data.get("name") or Path(path).stem),
        nodes=tuple(nodes),
    )


def resolve_graph_path(
    *,
    explicit: Path | str | None = None,
    cadre_root: Path | str | None = None,
    package_examples: Path | None = None,
) -> Path:
    """Prefer explicit → CADRE automation graph → bundled demo example."""
    if explicit is not None:
        path = Path(explicit)
        if not path.is_file():
            raise FileNotFoundError(f"campaign graph not found: {path}")
        return path

    if cadre_root is not None:
        candidate = Path(cadre_root) / "attack-matrix" / "Campaign" / "automation" / "campaign-graph.yaml"
        if candidate.is_file():
            return candidate

    env_raw = os.environ.get("CADRE_ROOT", "").strip()
    if env_raw:
        env_cadre = Path(env_raw)
        if env_cadre.is_dir():
            candidate = env_cadre / "attack-matrix" / "Campaign" / "automation" / "campaign-graph.yaml"
            if candidate.is_file():
                return candidate

    here = Path(__file__).resolve()
    for parent in here.parents:
        sibling = parent / "CADRE" / "attack-matrix" / "Campaign" / "automation" / "campaign-graph.yaml"
        if sibling.is_file():
            return sibling

    examples = package_examples or Path(__file__).resolve().parents[2] / "examples"
    fallback = examples / "campaign-graph.m1.yaml"
    if fallback.is_file():
        return fallback
    raise FileNotFoundError(
        "No campaign-graph.yaml found (set --graph or CADRE_ROOT, or install examples/)"
    )


def parse_phase_filter(phase_spec: str) -> Callable[[float], bool]:
    """Accept '1-3', '0.5-8', '1,2,3.5', or '6'."""
    clauses: list[tuple[str, float, float | None]] = []
    for part in phase_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = float(start_s), float(end_s)
            if end < start:
                raise ValueError(f"invalid phase range: {part}")
            clauses.append(("range", start, end))
        else:
            clauses.append(("exact", float(part), None))
    if not clauses:
        raise ValueError("no phases selected")

    def match(phase: float) -> bool:
        for kind, a, b in clauses:
            if kind == "exact" and phase == a:
                return True
            if kind == "range" and b is not None and a <= phase <= b:
                return True
        return False

    return match


def parse_branches(branch_spec: str | None) -> set[str]:
    """Default spine-only. Use 'all' or 'A,B,C' to include branches."""
    if not branch_spec or not str(branch_spec).strip():
        return {"spine"}
    raw = str(branch_spec).strip()
    if raw.lower() == "all":
        return set(KNOWN_BRANCHES)
    selected: set[str] = set()
    for part in raw.split(","):
        name = part.strip()
        if not name:
            continue
        # Normalize case for letter branches
        if len(name) == 1:
            name = name.upper()
        elif name.lower() == "sql-ai":
            name = "sql-ai"
        elif name.lower() == "spine":
            name = "spine"
        if name not in KNOWN_BRANCHES:
            raise ValueError(f"unknown branch '{part}'; known={sorted(KNOWN_BRANCHES)} or 'all'")
        selected.add(name)
    if "spine" not in selected and selected:
        # Operator asked only for branches — honor that
        return selected
    if not selected:
        return {"spine"}
    return selected


def _parse_node(item: dict[str, Any], index: int) -> CampaignNode:
    try:
        node_id = str(item["id"])
        phase = float(item["phase"])
        title = str(item["title"])
        path = str(item["path"])
    except KeyError as exc:
        raise ValueError(f"nodes[{index}] missing required field: {exc}") from exc

    stub = bool(item.get("stub") or False)
    script = item.get("script")
    if script is None:
        script = ""
    script = str(script)
    intent_raw = item.get("intent")
    intent = None if intent_raw in (None, "null") else str(intent_raw)
    intent_args = item.get("intent_args")
    if intent_args is not None and not isinstance(intent_args, dict):
        raise ValueError(f"nodes[{index}].intent_args must be a mapping")
    cred_raw = item.get("cred")
    cred = None if cred_raw in (None, "null") else str(cred_raw)
    if not stub and not script and not intent:
        raise ValueError(f"nodes[{index}] requires script, intent, or stub: true")

    beachheads_raw = item.get("beachheads") or ["windows", "linux"]
    if not isinstance(beachheads_raw, list):
        raise ValueError(f"nodes[{index}].beachheads must be a list")
    beachheads = tuple(str(b) for b in beachheads_raw)

    branch = str(item.get("branch") or "spine")
    if len(branch) == 1:
        branch = branch.upper()
    if branch not in KNOWN_BRANCHES:
        raise ValueError(f"nodes[{index}].branch invalid: {branch}")

    requires = item.get("requires_cred")
    produces = item.get("produces_cred")
    gate = item.get("hitl_gate")
    return CampaignNode(
        id=node_id,
        phase=phase,
        title=title,
        path=path,
        beachheads=beachheads,
        script=script,
        requires_cred=None if requires in (None, "null") else str(requires),
        produces_cred=None if produces in (None, "null") else str(produces),
        hitl_gate=None if gate in (None, "null") else str(gate),
        stub=stub,
        branch=branch,
        intent=intent,
        intent_args=dict(intent_args) if intent_args else None,
        cred=cred,
    )
