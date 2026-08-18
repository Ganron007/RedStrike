from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redstrike.runtime.beachhead import Beachhead, OperatorMode, detect_default_operator
from redstrike.runtime.hitl import EngagementStore, KNOWN_GATES
from redstrike.runtime.orchestrator import CampaignOrchestrator, StepResult


def default_automation_root() -> Path:
    import os

    env_raw = os.environ.get("REDSTRIKE_AUTOMATION_ROOT", "").strip() or os.environ.get(
        "CADRE_AUTOMATION_ROOT", ""
    ).strip()
    if env_raw:
        env = Path(env_raw)
        if env.is_dir():
            return env
    env_cadre = os.environ.get("CADRE_ROOT", "").strip()
    if env_cadre:
        candidate = Path(env_cadre) / "attack-matrix" / "04-automation" / "linux"
        if candidate.is_dir():
            return candidate
    return Path.cwd()


def default_seed_path() -> Path | None:
    """REDSTRIKE_SEED, then CADRE_ROOT lab seed (optional), then bundled placeholder."""
    import os

    env = os.environ.get("REDSTRIKE_SEED", "").strip()
    if env and Path(env).is_file():
        return Path(env)
    env_cadre = os.environ.get("CADRE_ROOT", "").strip()
    if env_cadre:
        candidate = Path(env_cadre) / "attack-matrix" / "Campaign" / "automation" / "lab-seed-creds.json"
        if candidate.is_file():
            return candidate
    example = Path(__file__).resolve().parents[2] / "examples" / "seed.example.json"
    return example if example.is_file() else None


class CampaignSession:
    """Facade for MCP/CLI: start → run_phase → approve → status."""

    def __init__(
        self,
        engagement_id: str,
        *,
        beachhead: str = "windows",
        operator: str | OperatorMode | None = None,
        automation_root: Path | str | None = None,
        graph_path: Path | str | None = None,
        cadre_root: Path | str | None = None,
        ledger_root: Path | None = None,
        allow_mbr01_stage: bool = False,
        seed_path: Path | str | None = None,
        branches: str | None = None,
        prefer_script: bool = False,
    ) -> None:
        self.engagement_id = engagement_id
        self.operator = OperatorMode(operator) if operator else detect_default_operator()
        self.automation_root = Path(automation_root) if automation_root else default_automation_root()
        self.graph_path = graph_path
        self.cadre_root = cadre_root
        self.ledger_root = ledger_root
        self.branches = branches
        self.prefer_script = prefer_script
        self.store = EngagementStore(engagement_id, root=ledger_root)
        self.state = self.store.get_or_create(
            beachhead=beachhead,
            allow_mbr01_stage=allow_mbr01_stage,
            operator=self.operator.value,
        )
        self.state.beachhead = beachhead
        self.state.operator = self.operator.value
        self.state.allow_mbr01_stage = allow_mbr01_stage
        self.store.save(self.state)
        self._seed(seed_path)

    def _seed(self, seed_path: Path | str | None) -> None:
        path = Path(seed_path) if seed_path else default_seed_path()
        if path and path.is_file():
            orch = self._orchestrator()
            orch.ledger.seed(json.loads(path.read_text(encoding="utf-8")))

    def _orchestrator(self) -> CampaignOrchestrator:
        return CampaignOrchestrator(
            engagement_id=self.engagement_id,
            beachhead=self.state.beachhead,
            operator=self.operator,
            automation_root=self.automation_root,
            graph_path=self.graph_path,
            cadre_root=self.cadre_root,
            ledger_root=self.ledger_root,
            allow_mbr01_stage=self.state.allow_mbr01_stage,
            engagement_state=self.state,
            branches=self.branches,
            prefer_script=self.prefer_script,
        )

    def start(self) -> dict[str, Any]:
        self.state.status = "running"
        self.store.save(self.state)
        return {
            "ok": True,
            "engagement_id": self.engagement_id,
            "beachhead": self.state.beachhead,
            "operator": self.operator.value,
            "allow_mbr01_stage": self.state.allow_mbr01_stage,
            "approved_gates": list(self.state.approved_gates),
            "known_gates": sorted(KNOWN_GATES),
            "branches": self.branches or "spine",
        }

    def approve(self, gate: str, *, note: str | None = None) -> dict[str, Any]:
        self.state.approve(gate, note=note)
        self.store.save(self.state)
        return {
            "ok": True,
            "engagement_id": self.engagement_id,
            "approved_gates": list(self.state.approved_gates),
            "pending_gate": self.state.pending_gate,
            "status": self.state.status,
        }

    def run_phase(
        self,
        phase: str = "1-3",
        *,
        dry_run: bool = True,
        stop_on_hitl: bool = True,
        profile: str | None = None,
        include_preflight: bool = True,
    ) -> dict[str, Any]:
        orch = self._orchestrator()
        results = orch.run(phase, dry_run=dry_run, stop_on_hitl=stop_on_hitl)
        self.state = orch.state
        summary = orch.summary(results)
        if include_preflight:
            summary["preflight"] = orch.preflight(profile=profile).to_dict()
        return summary

    def status(self) -> dict[str, Any]:
        state = self.store.load() or self.state
        orch = self._orchestrator()
        return {
            "engagement_id": self.engagement_id,
            "state": state.to_dict(),
            "ledger_creds": orch.ledger.names(),
            "graph": str(orch.graph_path),
            "graph_name": orch.graph.name,
            "known_gates": sorted(KNOWN_GATES),
            "beachhead": Beachhead(state.beachhead).value,
            "operator": self.operator.value,
            "branches": sorted(orch.branches),
            "preflight": orch.preflight().to_dict(),
        }


def results_have_failures(results: list[StepResult]) -> bool:
    return any(r.error and not r.skipped for r in results)
