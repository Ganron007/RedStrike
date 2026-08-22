from __future__ import annotations

from pathlib import Path

import pytest

from redstrike.runtime.graph import parse_branches
from redstrike.runtime.preflight import preflight
from redstrike.runtime.session import CampaignSession, default_seed_path

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
DEFAULT_GRAPH = EXAMPLES / "campaign-graph.m1.yaml"
SEED = EXAMPLES / "seed.example.json"


@pytest.fixture
def automation_root(tmp_path: Path) -> Path:
    root = tmp_path / "linux"
    scripts = [
        "campaign-a/demo-recon.sh",
        "campaign-a/demo-creds.sh",
        "campaign-a/demo-exec.sh",
        "campaign-a/demo-lateral.sh",
        "attacks/demo-acl.sh",
    ]
    for rel in scripts:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
    return root


def test_parse_branches_defaults_and_all() -> None:
    assert parse_branches(None) == {"spine"}
    assert parse_branches("A,b") == {"A", "B"}
    assert "sql-ai" in parse_branches("all")
    with pytest.raises(ValueError):
        parse_branches("Z")


def test_branch_filter_excludes_spine_when_only_a_standalone(
    automation_root: Path, tmp_path: Path
) -> None:
    session = CampaignSession(
        "br-a-demo",
        beachhead="windows",
        automation_root=automation_root,
        graph_path=DEFAULT_GRAPH,
        ledger_root=tmp_path / "ledgers",
        seed_path=SEED,
        branches="A",
    )
    summary = session.run_phase("4-5", dry_run=True, include_preflight=False)
    ids = {s["node_id"] for s in summary["steps"]}
    assert "DEMO-ACL" in ids
    assert "DEMO-RECON" not in ids
    assert summary["branches"] == ["A"]


def test_preflight_loads_profiles_yaml(tmp_path: Path) -> None:
    prof_file = tmp_path / "profiles.yaml"
    prof_file.write_text(
        """
version: 1
branch_defaults:
  D: "P-LINUX"
profiles:
  P-LINUX:
    required_hosts: ["linux01"]
hosts:
  linux01: "10.0.0.50"
""",
        encoding="utf-8",
    )
    result = preflight({"D"}, profiles_path=prof_file)
    assert result.profile == "P-LINUX"
    assert "linux01" in result.required_hosts
    assert result.host_ips["linux01"] == "10.0.0.50"


def test_default_seed_is_example_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REDSTRIKE_SEED", raising=False)
    path = default_seed_path()
    assert path is not None
    assert path.resolve() == SEED.resolve()


def test_default_seed_uses_redstrike_seed_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    custom_seed = tmp_path / "my-seed.json"
    custom_seed.write_text('{"admin": "password123"}', encoding="utf-8")
    monkeypatch.setenv("REDSTRIKE_SEED", str(custom_seed))
    path = default_seed_path()
    assert path is not None
    assert path.resolve() == custom_seed.resolve()
