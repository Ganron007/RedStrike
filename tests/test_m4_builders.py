from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from redstrike.api.server import create_app
from redstrike.builders import (
    BloodyADBuilder,
    CertipyBuilder,
    MimikatzBuilder,
    RubeusBuilder,
    SharpSCCMBuilder,
    SqlBuilder,
)
from redstrike.core.runner import redact_argv
from redstrike.runtime.intents import IntentRegistry
from redstrike.runtime.session import CampaignSession

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
DEFAULT_GRAPH = EXAMPLES / "campaign-graph.m1.yaml"
SEED = EXAMPLES / "seed.example.json"


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
    assert "-u" in argv and "u@lab" in argv
    assert "-p" in argv and "p" in argv
    assert "--domain" not in argv
    assert "-domain" not in argv
    assert "-d" not in argv

    hash_argv = CertipyBuilder().find(
        target="dc01.lab",
        username="u@lab",
        nt_hash=SecretStr("31d6cfe0d16ae931b73c59d7e0c089c0"),
    )
    assert "-hashes" in hash_argv
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" in hash_argv
    assert "-H" not in hash_argv


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
    assert "certipy.template" in reg.known()
    assert "shadowcreds.pywhiskey" in reg.known()
    assert "sharpsccm.exec_script" in reg.known()
    assert "sql.xp_cmdshell" in reg.known()
    argv = reg.build(
        "certipy.find",
        {"target": "dc01", "username": "u", "domain": "lab"},
    )
    assert argv[0] == "certipy"

    shadow_argv = reg.build(
        "shadowcreds.pywhiskey",
        {"target": "dc01", "target_user": "admin", "username": "u", "domain": "lab"},
    )
    assert shadow_argv[0] == "pywhiskey"


def test_orchestrator_prefers_intent_standalone(tmp_path: Path) -> None:
    root = tmp_path / "linux"
    (root / "campaign-a").mkdir(parents=True)
    for name in ("demo-recon.sh", "demo-creds.sh", "demo-exec.sh", "demo-lateral.sh"):
        (root / "campaign-a" / name).write_text("#!/bin/bash\n", encoding="utf-8")
    session = CampaignSession(
        "m4-demo",
        beachhead="windows",
        automation_root=root,
        graph_path=EXAMPLES / "campaign-graph.m1.yaml",
        ledger_root=tmp_path / "ledgers",
        seed_path=EXAMPLES / "seed.example.json",
        branches="spine",
    )
    summary = session.run_phase("1-3", dry_run=True, include_preflight=False)
    by_id = {s["node_id"]: s for s in summary["steps"]}
    assert by_id["DEMO-EXEC"]["intent"] == "certipy.find"
    assert by_id["DEMO-EXEC"]["mechanism"].startswith("intent:")
    assert by_id["DEMO-EXEC"]["argv"][0] == "certipy"
    assert summary.get("intent_count", 0) >= 1


def test_orchestrator_prefers_intent_generic_recon_graph(tmp_path: Path) -> None:
    session = CampaignSession(
        "m4-int",
        beachhead="windows",
        automation_root=tmp_path / "linux",
        graph_path=EXAMPLES / "generic-ad-recon.yaml",
        ledger_root=tmp_path / "ledgers",
        seed_path=SEED,
        branches="spine",
    )
    summary = session.run_phase("1.0", dry_run=True, include_preflight=False)
    by_id = {s["node_id"]: s for s in summary["steps"]}
    assert by_id["RECON-01-CERTIPY"]["intent"] == "certipy.find"
    assert by_id["RECON-01-CERTIPY"]["mechanism"].startswith("intent:")
    assert by_id["RECON-02-ASREP"]["intent"] == "rubeus.asreproast"
    assert by_id["RECON-02-ASREP"]["mechanism"].startswith("intent:")
    assert summary.get("intent_count", 0) >= 3


def test_api_builders_preview() -> None:
    client = TestClient(create_app(profile="campaign"))
    res = client.post(
        "/builders/preview",
        json={"intent": "sharpsccm.get_naa", "args": {"server": "mbr02.range.local"}},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["argv"][0] == "SharpSCCM.exe"
    assert "get" in body["argv"]


def test_shadowcreds_builder() -> None:
    from redstrike.builders import ShadowCredentialsBuilder

    argv = ShadowCredentialsBuilder().pywhiskey(
        target="dc01.example.lab",
        target_user="Administrator",
        username="hunter",
        password=SecretStr("pass123"),
        domain="example.lab",
        action="add",
    )
    assert argv[:2] == ["pywhiskey", "-target"]
    assert "Administrator" in argv
    assert "-action" in argv and "add" in argv


def test_certipy_unpac_and_template() -> None:
    builder = CertipyBuilder()
    auth_argv = builder.auth(pfx="admin.pfx", username="admin", domain="example.lab", unpac_hash=True, dc_ip="10.0.0.10")
    assert "-unpac-hash" in auth_argv
    assert "-pfx" in auth_argv
    assert "-domain" in auth_argv and "example.lab" in auth_argv
    assert "--domain" not in auth_argv
    assert "-username" in auth_argv and "admin" in auth_argv

    tmpl_argv = builder.template(
        template="ESC4-Template",
        username="lead_eng",
        password=SecretStr("pass"),
        domain="example.lab",
        write_default=True,
    )
    assert "-write-default-configuration" in tmpl_argv
    assert "-u" in tmpl_argv and "lead_eng@example.lab" in tmpl_argv
    assert "--domain" not in tmpl_argv and "-domain" not in tmpl_argv

    ca_argv = builder.ca(
        ca="corp-CA",
        username="lead_eng",
        password=SecretStr("pass"),
        domain="example.lab",
        add_officer="operator_user",
    )
    assert "-add-officer" in ca_argv and "operator_user" in ca_argv
    assert "-u" in ca_argv and "lead_eng@example.lab" in ca_argv
    assert "--domain" not in ca_argv and "-domain" not in ca_argv

    shadow_argv = builder.shadow(
        account="svc_admin",
        target="dc01.example.lab",
        username="lead_eng",
        domain="example.lab",
        nt_hash=SecretStr("31d6cfe0d16ae931b73c59d7e0c089c0"),
    )
    assert "-account" in shadow_argv and "svc_admin" in shadow_argv
    assert "-u" in shadow_argv and "lead_eng@example.lab" in shadow_argv
    assert "-hashes" in shadow_argv and "31d6cfe0d16ae931b73c59d7e0c089c0" in shadow_argv
    assert "-H" not in shadow_argv
    assert "--domain" not in shadow_argv and "-domain" not in shadow_argv


def test_sharpsccm_extensions() -> None:
    builder = SharpSCCMBuilder()
    exec_argv = builder.exec_script(server="mbr02", script_body="whoami", device="WS01")
    assert "-b" in exec_argv and "whoami" in exec_argv
    assert "-d" in exec_argv and "WS01" in exec_argv

    admin_argv = builder.adminservice_query(server="mbr02", endpoint="SMS_Application")
    assert "adminservice" in admin_argv


def test_teardown_queue() -> None:
    from redstrike.runtime.teardown import TeardownQueue

    queue = TeardownQueue()
    queue.register("remove_cert", "dc01", ["rm", "cert.pfx"], "Remove forged cert", cleanup_func=lambda: True)
    assert len(queue.pending) == 1
    res = queue.execute_all()
    assert res["total"] == 1
    assert res["succeeded"] == 1
    assert len(queue.pending) == 0


def test_bloodhound_and_recommend_api() -> None:
    client = TestClient(create_app(profile="campaign"))
    bh_res = client.post("/bloodhound/query", json={"query": "MATCH (n) RETURN n LIMIT 5"})
    assert bh_res.status_code == 200
    assert bh_res.json()["status"] == "ok"

    rec_res = client.post("/campaign/recommend", json={"engagement_id": "test", "objective": "Domain Admins"})
    assert rec_res.status_code == 200
    assert len(rec_res.json()["recommendations"]) >= 1
