from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from redstrike.runtime.hitl import KNOWN_GATES

KNOWN_BRANCHES = frozenset({"spine", "A", "B", "C", "D", "E", "F", "G", "H", "sql-ai"})

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
    pivot_to: str | None = None  # target machine/role for lateral movement
    produces_beachhead: str | None = None  # credential/beachhead this node creates
    success_marker: str | None = None  # regex; default {id with '-'→'_'}_OK
    fail_patterns: tuple[str, ...] = ()
    expected_errors: tuple[str, ...] = ()  # waived default fail patterns (e.g. T028)
    targets: tuple[str, ...] = ()  # explicit scope targets checked before live runs
    depends_on: tuple[str, ...] = ()  # node ids that must run (and verify) first
    when: dict[str, Any] | None = None  # run conditions: verified/unverified/cred (see CONDITION_KEYS)
    timeout_seconds: int | None = None  # per-node execution timeout override
    teardown: dict[str, Any] | None = None  # {"description": str, "command": [argv]} — reversible action
    idempotent: bool | None = None  # False: never auto-re-run after an unverified attempt
    #: Structured verification for JSON-emitting tools (az/Graph): {"path": "tenantId",
    #: "equals": "<value>"} — replaces the stdout marker when set.
    success_json: dict[str, str] | None = None


#: Supported `when:` condition keys (all values str or list[str]):
#:   verified:    listed node ids must have verified earlier in this run
#:   unverified:  listed node ids must NOT have verified (branch on failure)
#:   cred:        listed credential names must exist in the ledger
CONDITION_KEYS = ("verified", "unverified", "cred")

#: Intent-arg keys whose values are scope targets (checked against the scope
#: policy before live execution). "listener" is deliberately absent: coercion
#: listeners are OUR host, not a target.
TARGET_ARG_KEYS = (
    "target",
    "targets",
    "host",
    "hosts",
    "dc",
    "dc_ip",
    "server",
    "server_ip",
    "kdc",
    "kdc_host",
    "ca",
    "ca_host",
    "computer",
    "computers",
)

#: Intent-arg keys naming a CLOUD (Entra ID) target — validated against
#: allowed_tenants / allowed_cloud_domains instead of the host lists.
CLOUD_TARGET_ARG_KEYS = ("tenant", "tenant_id", "tenant_name", "cloud_domain")


def _as_str_tuple(value: Any, *, field: str, index: int) -> tuple[str, ...]:
    if value in (None, "", "null"):
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        items = tuple(str(item) for item in value if str(item).strip())
        if len(items) != len(value):
            raise ValueError(f"nodes[{index}].{field} entries must be non-empty strings")
        return items
    raise ValueError(f"nodes[{index}].{field} must be a string or list of strings")


def targets_from_args(args: dict[str, Any]) -> list[str]:
    """Every target-like value in an intent-args mapping (order preserved)."""
    values: list[str] = []
    for key in TARGET_ARG_KEYS:
        raw = args.get(key)
        if raw in (None, ""):
            continue
        if isinstance(raw, (list, tuple)):
            values.extend(str(item) for item in raw if str(item).strip())
        else:
            values.append(str(raw))
    seen: list[str] = []
    for value in values:
        text = value.strip()
        if text and text not in seen:
            seen.append(text)
    return seen


def collect_scope_targets(node: CampaignNode) -> list[str]:
    """Every scope target a node declares: explicit `target(s)` plus all
    target-like intent args (host/dc/kdc/ca/... — see TARGET_ARG_KEYS)."""
    values: list[str] = [str(item) for item in node.targets]
    seen: list[str] = []
    for value in [*values, *targets_from_args(node.intent_args or {})]:
        text = value.strip()
        if text and text not in seen:
            seen.append(text)
    return seen


def collect_cloud_targets(node: CampaignNode) -> list[str]:
    """Cloud (Entra ID) targets a node declares: `tenant:`-style intent args or
    an explicit `targets:` entry on a cloud-only node (see CLOUD_TARGET_ARG_KEYS)."""
    values: list[str] = []
    for key in CLOUD_TARGET_ARG_KEYS:
        raw = (node.intent_args or {}).get(key)
        if raw in (None, ""):
            continue
        if isinstance(raw, (list, tuple)):
            values.extend(str(item) for item in raw if str(item).strip())
        else:
            values.append(str(raw))
    seen: list[str] = []
    for value in values:
        text = value.strip()
        if text and text not in seen:
            seen.append(text)
    return seen


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
        raise TypeError("campaign graph must be a mapping")
    raw_nodes = data.get("nodes")
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise ValueError("campaign graph requires a non-empty nodes list")

    nodes: list[CampaignNode] = []
    for index, item in enumerate(raw_nodes):
        if not isinstance(item, dict):
            raise TypeError(f"nodes[{index}] must be a mapping")
        nodes.append(_parse_node(item, index))

    _validate_dependency_graph(nodes)

    return CampaignGraph(
        version=int(data.get("version") or 1),
        name=str(data.get("name") or Path(path).stem),
        nodes=tuple(nodes),
    )


def _validate_dependency_graph(nodes: list[CampaignNode]) -> None:
    """Fail fast on unknown dependency refs or cycles (see `depends_on`)."""
    by_id = {node.id: node for node in nodes}
    for node in nodes:
        for dep in node.depends_on:
            if dep not in by_id:
                raise ValueError(
                    f"node '{node.id}'.depends_on references unknown node '{dep}'"
                )
        for key in ("verified", "unverified"):
            for ref in (node.when or {}).get(key, []):
                if ref not in by_id:
                    raise ValueError(
                        f"node '{node.id}'.when.{key} references unknown node '{ref}'"
                    )

    visiting: set[str] = set()
    visited: set[str] = set()

    def _visit(node_id: str, chain: tuple[str, ...]) -> None:
        if node_id in visited:
            return
        if node_id in visiting:
            cycle = " -> ".join((*chain, node_id))
            raise ValueError(f"depends_on cycle detected: {cycle}")
        visiting.add(node_id)
        for dep in by_id[node_id].depends_on:
            _visit(dep, (*chain, node_id))
        visiting.discard(node_id)
        visited.add(node_id)

    for node in nodes:
        _visit(node.id, ())


def resolve_graph_path(
    *,
    explicit: Path | str | None = None,
    package_examples: Path | None = None,
) -> Path:
    """Prefer explicit --graph → REDSTRIKE_GRAPH env var → bundled generic graph."""
    if explicit is not None:
        path = Path(explicit)
        if not path.is_file():
            repo_root = Path(__file__).resolve().parents[2]
            if (repo_root / explicit).is_file():
                return repo_root / explicit
            if (repo_root / "examples" / explicit).is_file():
                return repo_root / "examples" / explicit
            data_dir = Path(__file__).resolve().parent.parent / "data"
            if (data_dir / explicit).is_file():
                return data_dir / explicit
            if (data_dir / path.name).is_file():
                return data_dir / path.name
            try:
                import importlib.resources as pkg_resources

                data_files = pkg_resources.files("redstrike.data")
                cand = data_files.joinpath(path.name)
                p = Path(str(cand))
                if p.is_file():
                    return p
            except Exception:
                pass
            raise FileNotFoundError(f"campaign graph not found: {path}")
        return path

    env_graph = os.environ.get("REDSTRIKE_GRAPH", "").strip()
    if env_graph and Path(env_graph).is_file():
        return Path(env_graph)

    cadre = os.environ.get("CADRE_ROOT", "").strip()
    if cadre:
        candidate = Path(cadre) / "attack-matrix" / "Campaign" / "automation" / "campaign-graph.yaml"
        if candidate.is_file():
            return candidate

    examples = package_examples or Path(__file__).resolve().parents[2] / "examples"
    for name in ("campaign-graph.m1.yaml", "generic-ad-recon.yaml"):
        fallback = examples / name
        if fallback.is_file():
            return fallback

    try:
        import importlib.resources as pkg_resources

        data_files = pkg_resources.files("redstrike.data")
        for name in ("campaign-graph.m1.yaml", "generic-ad-recon.yaml"):
            cand = data_files.joinpath(name)
            p = Path(str(cand))
            if p.is_file():
                return p
    except Exception:
        pass

    raise FileNotFoundError(
        "No campaign graph found (pass --graph, set REDSTRIKE_GRAPH, or check examples/)"
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
        if name.lower() in KNOWN_BRANCHES:
            name = name.lower()
        elif len(name) == 1:
            name = name.upper()
        if name not in KNOWN_BRANCHES:
            raise ValueError(f"unknown branch '{part}'; known={sorted(KNOWN_BRANCHES)} or 'all'")
        selected.add(name)
    return selected or {"spine"}


def parse_node_ids(node_spec: str | None) -> tuple[str, ...] | None:
    """Comma/semicolon-separated graph ids. Empty/None means no id filter."""
    if node_spec is None:
        return None
    raw = str(node_spec).strip()
    if not raw:
        return None
    seen: set[str] = set()
    ordered: list[str] = []
    for part in raw.replace(";", ",").split(","):
        node_id = part.strip()
        if not node_id or node_id in seen:
            continue
        seen.add(node_id)
        ordered.append(node_id)
    if not ordered:
        raise ValueError("no node ids selected")
    return tuple(ordered)


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
        raise TypeError(f"nodes[{index}].beachheads must be a list")
    beachheads = tuple(str(b) for b in beachheads_raw)

    branch = str(item.get("branch") or "spine")
    if len(branch) == 1:
        branch = branch.upper()
    if branch not in KNOWN_BRANCHES:
        raise ValueError(f"nodes[{index}].branch invalid: {branch}")

    requires = item.get("requires_cred")
    produces = item.get("produces_cred")
    gate = item.get("hitl_gate")
    if gate not in (None, "null") and str(gate) not in KNOWN_GATES:
        # An unknown gate can never be approved (approve() rejects it), which
        # would strand the node as "awaiting approval" forever — fail at load.
        raise ValueError(
            f"nodes[{index}].hitl_gate unknown: '{gate}' (known={sorted(KNOWN_GATES)})"
        )
    pivot_to = item.get("pivot_to")
    produces_beachhead = item.get("produces_beachhead")
    marker_raw = item.get("success_marker")
    success_marker = None if marker_raw in (None, "null", "") else str(marker_raw)

    targets = _as_str_tuple(item.get("targets") if item.get("targets") is not None else item.get("target"), field="targets", index=index)
    depends_on = _as_str_tuple(item.get("depends_on"), field="depends_on", index=index)
    if node_id in depends_on:
        raise ValueError(f"nodes[{index}].depends_on cannot reference the node itself")

    when_raw = item.get("when")
    when: dict[str, Any] | None = None
    if when_raw not in (None, "null"):
        if not isinstance(when_raw, dict) or not when_raw:
            raise ValueError(f"nodes[{index}].when must be a non-empty mapping")
        unknown_keys = [key for key in when_raw if key not in CONDITION_KEYS]
        if unknown_keys:
            raise ValueError(
                f"nodes[{index}].when has unsupported keys {unknown_keys} (known={list(CONDITION_KEYS)})"
            )
        when = {
            key: list(_as_str_tuple(value, field=f"when.{key}", index=index))
            for key, value in when_raw.items()
        }

    timeout_raw = item.get("timeout_seconds")
    timeout_seconds: int | None = None
    if timeout_raw not in (None, "null", ""):
        try:
            timeout_seconds = int(timeout_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"nodes[{index}].timeout_seconds must be an integer") from exc
        if timeout_seconds <= 0:
            raise ValueError(f"nodes[{index}].timeout_seconds must be positive")

    teardown_raw = item.get("teardown")
    teardown: dict[str, Any] | None = None
    if teardown_raw not in (None, "null"):
        if not isinstance(teardown_raw, dict) or not str(teardown_raw.get("description") or "").strip():
            raise ValueError(
                f"nodes[{index}].teardown must be a mapping with a 'description'"
            )
        command_raw = teardown_raw.get("command")
        command: list[str] | None = None
        if command_raw not in (None, "null", ""):
            command = [str(part) for part in _as_str_tuple(command_raw, field="teardown.command", index=index)]
        teardown = {
            "description": str(teardown_raw["description"]).strip(),
            "command": command,
        }

    idempotent_raw = item.get("idempotent")
    idempotent: bool | None = None
    if idempotent_raw not in (None, "null", ""):
        if isinstance(idempotent_raw, bool):
            idempotent = idempotent_raw
        elif str(idempotent_raw).strip().lower() in {"true", "yes", "1", "false", "no", "0"}:
            idempotent = str(idempotent_raw).strip().lower() in {"true", "yes", "1"}
        else:
            raise ValueError(f"nodes[{index}].idempotent must be a boolean")

    success_json_raw = item.get("success_json")
    success_json: dict[str, str] | None = None
    if success_json_raw not in (None, "null"):
        if not isinstance(success_json_raw, dict):
            raise ValueError(f"nodes[{index}].success_json must be a mapping")
        path_raw = success_json_raw.get("path")
        if path_raw in (None, "") :
            raise ValueError(f"nodes[{index}].success_json requires a 'path'")
        success_json = {
            "path": str(path_raw),
            "equals": str(success_json_raw.get("equals", "")),
        }

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
        pivot_to=None if pivot_to in (None, "null") else str(pivot_to),
        produces_beachhead=None if produces_beachhead in (None, "null") else str(produces_beachhead),
        success_marker=success_marker,
        fail_patterns=_parse_string_tuple(item.get("fail_patterns"), index, "fail_patterns"),
        expected_errors=_parse_string_tuple(item.get("expected_errors"), index, "expected_errors"),
        targets=targets,
        depends_on=depends_on,
        when=when,
        timeout_seconds=timeout_seconds,
        teardown=teardown,
        idempotent=idempotent,
        success_json=success_json,
    )


def _parse_string_tuple(raw: Any, index: int, field: str) -> tuple[str, ...]:
    if raw in (None, "null", ""):
        return ()
    if isinstance(raw, str):
        return (raw,)
    if not isinstance(raw, list):
        raise TypeError(f"nodes[{index}].{field} must be a string or list of strings")
    return tuple(str(item) for item in raw if item not in (None, ""))
