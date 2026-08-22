from __future__ import annotations

import json
from pathlib import Path

from redstrike.runtime.activity import ActivityJournal, resolve_activity_log, utc_now_ms
from redstrike.runtime.graph import resolve_graph_path
from redstrike.runtime.session import default_prefer_script


def test_utc_now_ms_is_iso_z() -> None:
    stamp = utc_now_ms()
    assert stamp.endswith("Z")
    assert "T" in stamp
    assert "." in stamp


def test_activity_journal_writes_jsonl_and_log(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    journal = ActivityJournal(path)
    journal.emit("step_start", engagement_id="e1", node_id="T003", title="AS-REP", argv=["nxc", "-p", "secret"])
    journal.emit("step_end", engagement_id="e1", node_id="T003", verified=True)

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["event"] == "step_start"
    assert first["node_id"] == "T003"
    assert "secret" not in path.read_text(encoding="utf-8")
    log = path.with_suffix(".log").read_text(encoding="utf-8")
    assert "T003" in log
    assert "step_start" in log


def test_resolve_activity_log_prefers_env(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "custom.jsonl"
    monkeypatch.setenv("REDSTRIKE_ACTIVITY_LOG", str(target))
    assert resolve_activity_log("eng") == target


def test_default_prefer_script_and_graph(tmp_path: Path, monkeypatch) -> None:
    custom_graph = tmp_path / "custom-graph.yaml"
    custom_graph.write_text("version: 1\nname: custom\nnodes:\n  - id: N1\n    phase: 1\n    title: Recon\n    path: direct\n    beachheads: [linux, windows]\n    script: ''\n    requires_cred: null\n    produces_cred: null\n", encoding="utf-8")
    monkeypatch.setenv("REDSTRIKE_GRAPH", str(custom_graph))
    monkeypatch.setenv("REDSTRIKE_PREFER_SCRIPT", "1")
    assert default_prefer_script() is True
    assert resolve_graph_path() == custom_graph

    monkeypatch.setenv("REDSTRIKE_PREFER_SCRIPT", "0")
    assert default_prefer_script() is False
