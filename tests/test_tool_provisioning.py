"""Tool-provisioning tests: container transport, ws01 tools-dir, pins, staging."""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path
from typing import ClassVar

import pytest

from redstrike.core.manifest import TOOL_MANIFEST, ToolSpec, probe_tool_version
from redstrike.core.runner import CommandRunner, linux_container
from redstrike.runtime.ws01_transport import wrap_argv_for_ws01, ws01_tools_dir

# ---------------------------------------------------------------------------
# Manifest provisioning data
# ---------------------------------------------------------------------------

def test_manifest_pins_and_platforms() -> None:
    by_name = {s.name: s for s in TOOL_MANIFEST}
    for pinned in ("sharphound", "mimikatz", "sharpsccm"):
        spec = by_name[pinned]
        assert spec.source_url and spec.sha256, pinned
        assert len(spec.sha256) == 64
    assert by_name["sharphound"].recommended_version == "2.17.0"
    assert by_name["sharphound"].source_member == "SharpHound.exe"
    assert by_name["mimikatz"].source_member == "x64/mimikatz.exe"
    # Windows-side tools carry stage names; Linux tools carry install recipes.
    assert by_name["rubeus"].platform == "windows" and by_name["rubeus"].stage_name == "Rubeus.exe"
    assert by_name["rubeus"].source_url is None  # source-only upstream — no fake pin
    # NetExec is NOT on PyPI (verified 2026-10-04: 404) — recipe uses the git repo
    assert "git+https://github.com/Pennyw0rth/NetExec" in (by_name["netexec"].install or "")
    # AzureHound is cross-platform.
    assert by_name["azurehound"].platform == "both"


# ---------------------------------------------------------------------------
# Container transport (C2Stack Kali)
# ---------------------------------------------------------------------------

class _FakePopen:
    captured: ClassVar[list[list[str]]] = []

    def __init__(self, argv, **kwargs):
        _FakePopen.captured.append(list(argv))
        self.returncode = 0

    def communicate(self, timeout=None):
        return b"ok", b""

    def kill(self):  # pragma: no cover - not hit in tests
        pass


def test_runner_wraps_tools_in_container(monkeypatch) -> None:
    from redstrike.core import runner as runner_mod

    _FakePopen.captured.clear()
    monkeypatch.setenv("REDSTRIKE_LINUX_CONTAINER", "c2stack-kali")
    monkeypatch.setattr(
        runner_mod,
        "subprocess",
        type("m", (), {"Popen": _FakePopen, "PIPE": -1, "CREATE_NEW_PROCESS_GROUP": 0}),
    )
    monkeypatch.setattr(runner_mod, "which", lambda name: "/usr/bin/docker" if name == "docker" else None)

    result = CommandRunner().run(["nxc", "--version"])
    assert result.return_code == 0
    assert _FakePopen.captured == [["docker", "exec", "-i", "c2stack-kali", "nxc", "--version"]]


def test_runner_never_wraps_transport_binaries(monkeypatch) -> None:
    from redstrike.core import runner as runner_mod

    _FakePopen.captured.clear()
    monkeypatch.setenv("REDSTRIKE_LINUX_CONTAINER", "c2stack-kali")
    monkeypatch.setattr(
        runner_mod,
        "subprocess",
        type("m", (), {"Popen": _FakePopen, "PIPE": -1, "CREATE_NEW_PROCESS_GROUP": 0}),
    )
    monkeypatch.setattr(runner_mod, "resolve_executable", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(runner_mod, "which", lambda name: f"/usr/bin/{name}")

    CommandRunner().run(["ssh", "ws01", "whoami"])
    assert _FakePopen.captured[0][0] == "/usr/bin/ssh"  # not docker-wrapped


def test_linux_container_env(monkeypatch) -> None:
    monkeypatch.delenv("REDSTRIKE_LINUX_CONTAINER", raising=False)
    assert linux_container() is None
    monkeypatch.setenv("REDSTRIKE_LINUX_CONTAINER", " c2stack-kali ")
    assert linux_container() == "c2stack-kali"


def test_container_aware_probe(monkeypatch) -> None:
    from redstrike.core import manifest as manifest_mod

    captured: ClassVar[list[list[str]]] = []

    class _Done:
        returncode = 0
        stdout = '{"azure-cli": "2.82.0"}'
        stderr = ""

    monkeypatch.setattr(
        manifest_mod.subprocess, "run", lambda cmd, **kw: (captured.append(list(cmd)), _Done())[1]
    )
    spec = next(s for s in TOOL_MANIFEST if s.name == "az")
    status = probe_tool_version(spec, exec_prefix=("docker", "exec", "-i", "c2stack-kali"))
    assert status.found and status.version == "2.82.0"
    assert captured[0][:4] == ["docker", "exec", "-i", "c2stack-kali"]
    assert "c2stack-kali:az" in status.path


# ---------------------------------------------------------------------------
# Windows tools-dir autodiscovery
# ---------------------------------------------------------------------------

def test_ws01_tools_dir_and_resolution(monkeypatch) -> None:
    from redstrike.runtime import ws01_transport as transport

    monkeypatch.setenv("REDSTRIKE_WS01_TOOLS_DIR", "C:\\Tools;D:\\RedTeam")
    monkeypatch.setenv("REDSTRIKE_WS01_HOST", "ws01.lab")
    monkeypatch.setattr(transport.shutil, "which", lambda name: r"C:\Windows\ssh.exe")
    assert ws01_tools_dir() == "C:\\Tools"

    wrapped = wrap_argv_for_ws01(["Rubeus.exe", "asreproast", "/format:hashcat"])
    remote_command = wrapped[-1]
    assert "C:\\Tools\\Rubeus.exe" in remote_command
    assert "asreproast" in remote_command

    # Non-executables and explicit paths are never prefixed.
    assert "C:\\\\Tools\\\\bash" not in " ".join(wrap_argv_for_ws01(["bash", "script.sh"]))
    explicit = wrap_argv_for_ws01(["C:\\Other\\Rubeus.exe", "asreproast"])
    assert "C:\\Tools\\C:\\Other" not in explicit[-1]


def test_ws01_tools_dir_unset(monkeypatch) -> None:
    monkeypatch.delenv("REDSTRIKE_WS01_TOOLS_DIR", raising=False)
    assert ws01_tools_dir() is None


# ---------------------------------------------------------------------------
# `redstrike stage`
# ---------------------------------------------------------------------------

def test_stage_plan_lists_pins(monkeypatch, capsys) -> None:
    from redstrike.cli import stage as stage_cli

    monkeypatch.setenv("REDSTRIKE_WS01_TOOLS_DIR", "C:\\Tools")
    assert stage_cli.main(["--plan", "--json"]) == 0
    import json as _json

    payload = _json.loads(capsys.readouterr().out)
    by_tool = {row["tool"]: row for row in payload["windows_tools"]}
    assert by_tool["mimikatz"]["pinned"] is True
    assert by_tool["rubeus"]["pinned"] is False
    assert by_tool["mimikatz"]["target"] == "C:\\Tools\\mimikatz.exe"


def test_stage_file_hash_mismatch_refused(monkeypatch, tmp_path, capsys) -> None:
    from redstrike.cli import stage as stage_cli

    monkeypatch.setenv("REDSTRIKE_WS01_TOOLS_DIR", "C:\\Tools")
    monkeypatch.setenv("REDSTRIKE_WS01_HOST", "ws01.lab")
    fake = tmp_path / "SharpSCCM.exe"  # pinned artifact that is NOT an archive
    fake.write_bytes(b"NOT the real SharpSCCM")
    rc = stage_cli.main(["--tool", "sharpsccm", "--file", str(fake)])
    assert rc == 2
    assert "MISMATCH" in capsys.readouterr().err


def test_stage_file_unpinned_records_hash(monkeypatch, tmp_path, capsys) -> None:
    from redstrike.cli import stage as stage_cli

    payload = b"MZ-fake-rubeus"
    expected_sha = hashlib.sha256(payload).hexdigest()
    local = tmp_path / "Rubeus.exe"
    local.write_bytes(payload)

    monkeypatch.setenv("REDSTRIKE_WS01_TOOLS_DIR", "C:\\Tools")
    monkeypatch.setenv("REDSTRIKE_WS01_HOST", "ws01.lab")
    pushed: dict = {}

    def fake_ensure(settings, directory):
        pushed["dir"] = directory

    def fake_push(settings, local_path, directory, stage_name):
        pushed["stage_name"] = stage_name
        return f"{directory}\\{stage_name}"

    monkeypatch.setattr(stage_cli, "_ensure_remote_dir", fake_ensure)
    monkeypatch.setattr(stage_cli, "_push", fake_push)
    rc = stage_cli.main(["--tool", "rubeus", "--file", str(local), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert pushed["dir"] == "C:\\Tools" and pushed["stage_name"] == "Rubeus.exe"
    import json as _json

    result = _json.loads(out)
    assert result["sha256"] == expected_sha
    assert result["verified"] is False  # unpinned: recorded, not claimed as verified


def test_stage_file_archive_pin_not_applied_to_extracted(monkeypatch, tmp_path, capsys) -> None:
    """mimikatz's pin covers the zip; a direct mimikatz.exe gets its hash recorded."""
    from redstrike.cli import stage as stage_cli

    local = tmp_path / "mimikatz.exe"
    local.write_bytes(b"MZ-extracted-mimikatz")
    monkeypatch.setenv("REDSTRIKE_WS01_TOOLS_DIR", "C:\\Tools")
    monkeypatch.setenv("REDSTRIKE_WS01_HOST", "ws01.lab")
    monkeypatch.setattr(stage_cli, "_ensure_remote_dir", lambda s, d: None)
    monkeypatch.setattr(stage_cli, "_push", lambda s, p, d, n: f"{d}\\{n}")
    rc = stage_cli.main(["--tool", "mimikatz", "--file", str(local), "--json"])
    assert rc == 0
    import json as _json

    result = _json.loads(capsys.readouterr().out)
    assert result["verified"] is False
    assert "covers the upstream archive" in result["note"]


def test_stage_download_happy_path(monkeypatch, tmp_path, capsys) -> None:
    """A pinned tool: fake the artifact + hash, verify extraction and push."""
    from redstrike.cli import stage as stage_cli

    member_bytes = b"MZ-realistic-test-binary"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("x64/mimikatz.exe", member_bytes)
    archive_bytes = buffer.getvalue()
    archive_sha = hashlib.sha256(archive_bytes).hexdigest()

    spec = ToolSpec(
        name="mimikatz",
        aliases=("mimikatz.exe",),
        category="test",
        purpose="test",
        platform="windows",
        stage_name="mimikatz.exe",
        source_url="https://example.test/mimikatz_trunk.zip",
        source_member="x64/mimikatz.exe",
        sha256=archive_sha,
    )
    monkeypatch.setattr(stage_cli, "_tool", lambda name: spec)
    monkeypatch.setattr(stage_cli, "_fetch", lambda url: archive_bytes)
    monkeypatch.setattr(stage_cli, "_ensure_remote_dir", lambda s, d: None)
    pushed: dict = {}

    def fake_push(settings, local_path, directory, stage_name):
        pushed["bytes"] = local_path.read_bytes()
        return f"{directory}\\{stage_name}"

    monkeypatch.setattr(stage_cli, "_push", fake_push)
    monkeypatch.setenv("REDSTRIKE_WS01_TOOLS_DIR", "C:\\Tools")
    monkeypatch.setenv("REDSTRIKE_WS01_HOST", "ws01.lab")

    rc = stage_cli.main(["--tool", "mimikatz", "--download", "--json"])
    assert rc == 0
    assert pushed["bytes"] == member_bytes  # extracted, not the zip
    import json as _json

    result = _json.loads(capsys.readouterr().out)
    assert result["verified"] is True
    assert result["sha256"] == hashlib.sha256(member_bytes).hexdigest()


def test_stage_download_unpinned_refused(monkeypatch, capsys) -> None:
    from redstrike.cli import stage as stage_cli

    monkeypatch.setenv("REDSTRIKE_WS01_TOOLS_DIR", "C:\\Tools")
    monkeypatch.setenv("REDSTRIKE_WS01_HOST", "ws01.lab")
    rc = stage_cli.main(["--tool", "rubeus", "--download"])
    assert rc == 2
    assert "no pinned upstream artifact" in capsys.readouterr().err


def test_extract_member_reports_available_names() -> None:
    from redstrike.cli.stage import _extract_member

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.txt", b"a")
    with pytest.raises(KeyError, match="a.txt"):
        _extract_member(buffer.getvalue(), "missing.exe", url="https://x/y.zip")


def test_stage_requires_tools_dir(monkeypatch, tmp_path, capsys) -> None:
    from redstrike.cli import stage as stage_cli

    monkeypatch.delenv("REDSTRIKE_WS01_TOOLS_DIR", raising=False)
    local = tmp_path / "Rubeus.exe"
    local.write_bytes(b"MZ")
    with pytest.raises(SystemExit):
        stage_cli.main(["--tool", "rubeus", "--file", str(local)])


# ---------------------------------------------------------------------------
# Remote-Linux SSH transport (RedStrike on Windows -> Kali)
# ---------------------------------------------------------------------------

def test_linux_ssh_base_from_env(monkeypatch) -> None:
    from redstrike.core.runner import linux_ssh_base

    monkeypatch.delenv("REDSTRIKE_LINUX_SSH", raising=False)
    assert linux_ssh_base() is None
    monkeypatch.setenv("REDSTRIKE_LINUX_SSH", "operator@kali.lab")
    monkeypatch.setenv("REDSTRIKE_LINUX_SSH_KEY", r"C:\keys\kali.key")
    base = linux_ssh_base()
    assert base is not None
    assert base[0] == "ssh" and base[-1] == "operator@kali.lab"
    assert "BatchMode=yes" in base and "-i" in base
    monkeypatch.setenv("REDSTRIKE_LINUX_SSH", "operator@kali.lab:2222")
    assert linux_ssh_base()[-3:-1] == ["-p", "2222"]


def test_runner_ssh_wraps_with_quoting_and_redacts_display(monkeypatch) -> None:
    from redstrike.core import runner as runner_mod

    _FakePopen.captured.clear()
    monkeypatch.setenv("REDSTRIKE_LINUX_SSH", "operator@kali.lab")
    monkeypatch.delenv("REDSTRIKE_LINUX_CONTAINER", raising=False)
    monkeypatch.setattr(
        runner_mod,
        "subprocess",
        type("m", (), {"Popen": _FakePopen, "PIPE": -1, "CREATE_NEW_PROCESS_GROUP": 0}),
    )
    monkeypatch.setattr(runner_mod, "which", lambda name: "/usr/bin/ssh" if name == "ssh" else None)

    result = CommandRunner().run(["certipy", "auth", "-p", "s3cret", "-target", "dc01.corp.local"])
    executed = _FakePopen.captured[0]
    assert executed[0] == "ssh" and executed[-1].startswith("certipy auth")
    assert "s3cret" in executed[-1]  # real secret executed
    assert result.command[-1].count("***REDACTED***") == 1  # display redacted
    assert "s3cret" not in " ".join(result.command)


def test_runner_conflicts_container_and_ssh(monkeypatch) -> None:
    monkeypatch.setenv("REDSTRIKE_LINUX_CONTAINER", "c2stack-kali")
    monkeypatch.setenv("REDSTRIKE_LINUX_SSH", "operator@kali.lab")
    with pytest.raises(ValueError, match="pick exactly one"):
        CommandRunner().run(["nxc", "--version"])


def test_local_tools_dir_resolution(monkeypatch, tmp_path) -> None:
    from redstrike.core.runner import resolve_executable

    tools = tmp_path / "tools"
    tools.mkdir()
    fake = tools / "rs-demo-tool.cmd"
    fake.write_text("@echo off\necho from-tools-dir\n", encoding="utf-8")
    monkeypatch.setenv("REDSTRIKE_LOCAL_TOOLS_DIR", str(tools))
    assert resolve_executable("rs-demo-tool.cmd") == str(fake)
    # multi-dir: second entry also resolves
    other = tmp_path / "other"
    other.mkdir()
    second = other / "rs-second.cmd"
    second.write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setenv("REDSTRIKE_LOCAL_TOOLS_DIR", f"{tools};{other}")
    assert resolve_executable("rs-second.cmd") == str(second)


def test_manifest_ssh_probe(monkeypatch) -> None:
    from redstrike.core import manifest as manifest_mod

    captured: list[list[str]] = []

    class _Done:
        returncode = 0
        stdout = '{"azure-cli": "2.82.0"}'
        stderr = ""

    monkeypatch.setattr(
        manifest_mod.subprocess, "run", lambda cmd, **kw: (captured.append(list(cmd)), _Done())[1]
    )
    spec = next(s for s in TOOL_MANIFEST if s.name == "az")
    status = probe_tool_version(spec, ssh_base=("ssh", "operator@kali.lab"))
    assert status.found and status.version == "2.82.0"
    assert captured[0][0] == "ssh" and captured[0][1] == "operator@kali.lab"
    assert captured[0][-1] == "az version"  # single quoted remote command
    assert "operator@kali.lab:az" in status.path


def test_audit_unreachable_ssh_reports_not_probed(monkeypatch) -> None:
    from redstrike.core.manifest import audit_toolchain

    statuses = audit_toolchain(
        ssh_base=("ssh", "operator@kali.lab"), ssh_reachable=False
    )
    by_name = {s.name: s for s in statuses}
    netexec = by_name["netexec"]
    assert netexec.found is False and netexec.is_compatible is True
    assert "unreachable" in netexec.detail
    # windows-side tools still report the staging hint, not ssh noise
    assert "stage to the beachhead" in by_name["rubeus"].detail


def test_check_topology_and_conflict_item(monkeypatch) -> None:
    from redstrike.cli import check as check_mod

    monkeypatch.setattr(check_mod, "linux_container", lambda: "c2stack-kali")
    monkeypatch.setenv("REDSTRIKE_LINUX_SSH", "operator@kali.lab")
    monkeypatch.setenv("REDSTRIKE_WS01_HOST", "192.168.77.62")
    monkeypatch.setenv("REDSTRIKE_WS01_TOOLS_DIR", r"C:\Tools")
    topo = check_mod.topology()
    assert "CONFLICT" in (topo["linux_execution"] or "")
    assert topo["windows_execution"] == "ssh:192.168.77.62"
    assert topo["windows_tools_dir"] == r"C:\Tools"

    monkeypatch.setattr(check_mod, "_ssh_probe_once", lambda base: False)
    monkeypatch.setattr(check_mod.shutil, "which", lambda name: f"/usr/bin/{name}")
    items = check_mod.collect_checks(scope_path=Path("missing-scope.yaml"))
    by_name = {i.name: i for i in items}
    assert by_name["linux-target"].ok is False
    assert "CONFLICT" in by_name["linux-target"].detail
    assert by_name["linux-ssh"].ok is False
    assert "UNREACHABLE" in by_name["linux-ssh"].detail


def test_check_topology_local_defaults(monkeypatch) -> None:
    from redstrike.cli import check as check_mod

    for var in (
        "REDSTRIKE_LINUX_CONTAINER",
        "REDSTRIKE_LINUX_SSH",
        "REDSTRIKE_WS01_HOST",
        "REDSTRIKE_WS01_TOOLS_DIR",
        "REDSTRIKE_LOCAL_TOOLS_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    topo = check_mod.topology()
    assert topo["linux_execution"] == "local"
    assert topo["windows_execution"].startswith("local")


# ---------------------------------------------------------------------------
# `redstrike install` (Linux host provisioning)
# ---------------------------------------------------------------------------

def test_install_executable_recipe_detection() -> None:
    from redstrike.cli.install import executable_recipe

    assert executable_recipe("pip install certipy-ad") == ["pip", "install", "certipy-ad"]
    assert executable_recipe("pip install netexec  # or: apt install netexec") == [
        "pip", "install", "netexec",
    ]
    assert executable_recipe("go install github.com/ropnop/kerbrute@latest  # or grab a release binary") == [
        "go", "install", "github.com/ropnop/kerbrute@latest",
    ]
    assert executable_recipe("Linux: apt/curl azure-cli | Windows: MSI installer") is None
    assert executable_recipe("Install-Module AADInternals  # PowerShell") is None
    assert executable_recipe(None) is None


def test_install_plan_json(monkeypatch, capsys) -> None:
    from redstrike.cli import install as install_cli

    monkeypatch.delenv("REDSTRIKE_LINUX_CONTAINER", raising=False)
    monkeypatch.delenv("REDSTRIKE_LINUX_SSH", raising=False)
    assert install_cli.main(["--plan", "--json"]) == 0
    import json as _json

    payload = _json.loads(capsys.readouterr().out)
    assert payload["target"] == "local"
    by_tool = {row["tool"]: row for row in payload["linux_tools"]}
    assert by_tool["certipy"]["executable"] is True
    assert by_tool["az"]["executable"] is False  # prose recipe -> manual


def test_install_apply_uses_runner_transport(monkeypatch, capsys) -> None:
    """--apply dispatches recipes through CommandRunner (so ssh/container wrap applies)."""
    from redstrike.cli import install as install_cli
    from redstrike.core import runner as runner_mod

    captured: list[list[str]] = []

    class _Result:
        return_code = 0
        stdout = "installed"
        stderr = ""

    def fake_run(self, command, *, timeout_seconds=None):
        captured.append(list(command))
        return _Result()

    monkeypatch.setattr(runner_mod.CommandRunner, "run", fake_run)
    monkeypatch.setenv("REDSTRIKE_LINUX_SSH", "operator@prov.lab")
    assert install_cli.main(["--apply", "--only", "certipy,impacket", "--json"]) == 0
    import json as _json

    payload = _json.loads(capsys.readouterr().out)
    assert payload["target"] == "ssh:operator@prov.lab"
    assert captured == [["pip", "install", "certipy-ad"], ["pip", "install", "impacket"]]
    statuses = {r["tool"]: r["status"] for r in payload["results"]}
    assert statuses == {"certipy": "installed", "impacket": "installed"}


def test_install_apply_reports_failures(monkeypatch, capsys) -> None:
    from redstrike.cli import install as install_cli
    from redstrike.core import runner as runner_mod

    class _Bad:
        return_code = 1
        stdout = ""
        stderr = "network unreachable"

    monkeypatch.setattr(runner_mod.CommandRunner, "run", lambda self, cmd, **kw: _Bad())
    monkeypatch.delenv("REDSTRIKE_LINUX_SSH", raising=False)
    monkeypatch.delenv("REDSTRIKE_LINUX_CONTAINER", raising=False)
    rc = install_cli.main(["--apply", "--only", "certipy"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAIL" in out


def test_linux_ssh_host_key_policy(monkeypatch) -> None:
    from redstrike.core.runner import linux_ssh_base

    monkeypatch.setenv("REDSTRIKE_LINUX_SSH", "root@prov.lab")
    monkeypatch.delenv("REDSTRIKE_LINUX_SSH_KNOWN_HOSTS", raising=False)
    base = linux_ssh_base()
    assert "StrictHostKeyChecking=accept-new" in base  # fresh box must not dead-end

    monkeypatch.setenv("REDSTRIKE_LINUX_SSH_KNOWN_HOSTS", "C:/keys/prov.known_hosts")
    base = linux_ssh_base()
    assert "StrictHostKeyChecking=yes" in base
    assert any("UserKnownHostsFile=C:/keys/prov.known_hosts" == part for part in base)


def test_install_retries_externally_managed_pip(monkeypatch, capsys) -> None:
    from redstrike.cli import install as install_cli
    from redstrike.core import runner as runner_mod

    calls: list[list[str]] = []

    class _Pep668:
        return_code = 1
        stdout = ""
        stderr = "error: externally-managed-environment. See PEP 668 for more information."

    class _Ok:
        return_code = 0
        stdout = "installed"
        stderr = ""

    def fake_run(self, command, *, timeout_seconds=None):
        calls.append(list(command))
        return _Pep668() if len(calls) == 1 else _Ok()

    monkeypatch.setattr(runner_mod.CommandRunner, "run", fake_run)
    monkeypatch.delenv("REDSTRIKE_LINUX_SSH", raising=False)
    monkeypatch.delenv("REDSTRIKE_LINUX_CONTAINER", raising=False)
    rc = install_cli.main(["--apply", "--only", "certipy", "--json"])
    assert rc == 0
    import json as _json

    payload = _json.loads(capsys.readouterr().out)
    assert calls[1] == ["pip", "install", "certipy-ad", "--break-system-packages"]
    assert payload["results"][0]["status"] == "installed"
    assert "break-system-packages" in payload["results"][0]["note"]


# ---------------------------------------------------------------------------
# Isolation + canonical env names
# ---------------------------------------------------------------------------

def test_canonical_windows_env_with_ws01_alias(monkeypatch) -> None:
    from redstrike.core.env import windows_host, windows_tools_dir, windows_user

    monkeypatch.setenv("REDSTRIKE_WS01_HOST", "legacy.host")
    assert windows_host() == "legacy.host"  # back-compat alias
    monkeypatch.setenv("REDSTRIKE_WINDOWS_HOST", "canonical.host")
    assert windows_host() == "canonical.host"  # canonical wins
    monkeypatch.setenv("REDSTRIKE_WINDOWS_TOOLS_DIR", r"C:\Tools")
    assert windows_tools_dir() == r"C:\Tools"
    assert windows_user() == ""


def test_linux_remote_tools_dir_resolution(monkeypatch) -> None:
    from redstrike.core import runner as runner_mod

    _FakePopen.captured.clear()
    monkeypatch.setenv("REDSTRIKE_LINUX_SSH", "ops@prov.lab")
    monkeypatch.setenv("REDSTRIKE_LINUX_TOOLS_DIR", "/opt/redstrike/venv/bin")
    monkeypatch.delenv("REDSTRIKE_LINUX_CONTAINER", raising=False)
    monkeypatch.setattr(
        runner_mod,
        "subprocess",
        type("m", (), {"Popen": _FakePopen, "PIPE": -1, "CREATE_NEW_PROCESS_GROUP": 0}),
    )
    monkeypatch.setattr(runner_mod, "which", lambda name: "/usr/bin/ssh" if name == "ssh" else None)

    CommandRunner().run(["certipy", "find", "-u", "analyst_t1"])
    executed = _FakePopen.captured[0]
    assert "/opt/redstrike/venv/bin/certipy" in executed[-1]  # venv bin resolved
    assert "analyst_t1" in executed[-1]

    # explicit paths are never rewritten
    _FakePopen.captured.clear()
    CommandRunner().run(["/usr/bin/nmap", "-sV"])
    assert "/opt/redstrike/venv/bin/usr" not in _FakePopen.captured[0][-1]


def test_install_venv_mode(monkeypatch, capsys) -> None:
    from redstrike.cli import install as install_cli
    from redstrike.core import runner as runner_mod

    calls: list[list[str]] = []

    class _Ok:
        return_code = 0
        stdout = ""
        stderr = ""

    def fake_run(self, command, *, timeout_seconds=None):
        calls.append(list(command))
        return _Ok()

    monkeypatch.setattr(runner_mod.CommandRunner, "run", fake_run)
    monkeypatch.setenv("REDSTRIKE_LINUX_SSH", "ops@prov.lab")
    rc = install_cli.main(
        ["--apply", "--only", "certipy,kerbrute", "--venv", "/opt/redstrike/venv", "--json"]
    )
    assert rc == 0
    assert calls[0] == ["python3", "-m", "venv", "/opt/redstrike/venv"]  # venv created first
    assert ["/opt/redstrike/venv/bin/pip", "install", "certipy-ad"] in calls
    assert ["go", "install", "github.com/ropnop/kerbrute@latest"] in calls  # go stays system
    import json as _json

    payload = _json.loads(capsys.readouterr().out)
    assert payload["venv"] == "/opt/redstrike/venv"
    assert "REDSTRIKE_LINUX_TOOLS_DIR=/opt/redstrike/venv/bin" in payload["next"]
