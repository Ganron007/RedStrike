from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from cadre_strike.api.server import create_app
from cadre_strike.builders import (
    BloodyADBuilder,
    CertipyBuilder,
    MimikatzBuilder,
    RubeusBuilder,
    SharpSCCMBuilder,
    SqlBuilder,
)
from cadre_strike.core.runner import redact_argv
from cadre_strike.runtime.intents import IntentRegistry
from cadre_strike.runtime.session import CampaignSession

CADRE_AUTO = (
    Path(__file__).resolve().parents[2]
    / "CADRE"
    / "attack-matrix"
    / "Campaign"
    / "automation"
)
GRAPH = CADRE_AUTO / "campaign-graph.yaml"
SEED = CADRE_AUTO / "lab-seed-creds.json"


def test_certipy_find_builder() -> None:
    argv = CertipyBuilder().find(
        target="dc01.lab",
        username="u",
        password=SecretStr("p"),
        domain="lab",
        vulnerable=True,
    )
    assert argv[:2] == ["certipy", "find"]
    assert "-vulnerable" in argv
    assert "-p" in argv and "p" in argv


def test_rubeus_asktgt_requires_secret() -> None:
    with pytest.raises(ValueError):
        RubeusBuilder().asktgt(user="u", domain="lab")
    argv = RubeusBuilder().asktgt(user="u", domain="lab", password=SecretStr("x"))
    assert any(a.startswith("/password:") for a in argv)


def test_bloodyad_set_password() -> None:
    argv = BloodyADBuilder().set_password(
        host="dc",
        username="a",
        target="b",
        new_password=SecretStr("n"),
        password=SecretStr("p"),
        domain="lab",
    )
    assert argv[0] == "bloodyAD"
    assert "set" in argv and "password" in argv


def test_sql_redacts_embedded_password() -> None:
    argv = SqlBuilder().mssqlclient(
        target="192.168.1.1",
        username="u",
        password=SecretStr("Secret!"),
        domain="lab",
    )
    red = redact_argv(argv)
    assert any("***REDACTED***" in part for part in red)
    assert not any("Secret!" in part for part in red)


def test_sharpsccm_and_mimikatz() -> None:
    assert SharpSCCMBuilder().get_naa(server="mbr02")[0].endswith("SharpSCCM.exe") or True
    assert "sekurlsa::logonpasswords" in MimikatzBuilder().logonpasswords()


def test_intent_registry_known() -> None:
    reg = IntentRegistry()
    assert "certipy.find" in reg.known()
    assert "sql.xp_cmdshell" in reg.known()
    argv = reg.build(
        "certipy.find",
        {"target": "dc01", "username": "u", "domain": "lab"},
    )
    assert argv[0] == "certipy"


@pytest.mark.skipif(not GRAPH.is_file(), reason="CADRE graph missing")
def test_orchestrator_prefers_intent(tmp_path: Path) -> None:
    root = tmp_path / "linux"
    (root / "campaign-a").mkdir(parents=True)
    for name in ("T003-asrep-ws01.sh", "T002-kerb-ws01.sh", "T041-xpcmd-ws01.sh", "T043-impersonate-ws01.sh"):
        (root / "campaign-a" / name).write_text("#!/bin/bash\n", encoding="utf-8")
    session = CampaignSession(
        "m4-int",
        beachhead="windows",
        automation_root=root,
        graph_path=GRAPH,
        ledger_root=tmp_path / "ledgers",
        seed_path=SEED if SEED.is_file() else None,
        branches="spine",
    )
    summary = session.run_phase("1-3", dry_run=True, include_preflight=False)
    by_id = {s["node_id"]: s for s in summary["steps"]}
    assert by_id["T003"]["intent"] == "rubeus.asreproast"
    assert by_id["T003"]["mechanism"].startswith("intent:")
    assert by_id["T003"]["argv"][0] == "Rubeus.exe"
    assert summary.get("intent_count", 0) >= 3


def test_api_builders_preview() -> None:
    client = TestClient(create_app(profile="cadre-campaign"))
    res = client.post(
        "/builders/preview",
        json={"intent": "sharpsccm.get_naa", "args": {"server": "mbr02.range.local"}},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["argv"][0] == "SharpSCCM.exe"
    assert "get" in body["argv"]
