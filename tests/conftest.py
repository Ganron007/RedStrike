from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_redstrike_process_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep test environment isolated and clean across runs."""
    monkeypatch.delenv("REDSTRIKE_REQUIRE_HITL", raising=False)
    monkeypatch.setenv("REDSTRIKE_UNGATED", "")
    monkeypatch.delenv("REDSTRIKE_UNGATED", raising=False)
    monkeypatch.delenv("REDSTRIKE_SCOPE", raising=False)
    monkeypatch.delenv("REDSTRIKE_PREFER_SCRIPT", raising=False)
    monkeypatch.delenv("REDSTRIKE_ACTIVITY_LOG", raising=False)
    monkeypatch.delenv("REDSTRIKE_GRAPH", raising=False)
    monkeypatch.delenv("REDSTRIKE_SEED", raising=False)
    monkeypatch.delenv("REDSTRIKE_AUTOMATION_ROOT", raising=False)
