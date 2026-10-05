from __future__ import annotations

import os
import shutil

from redstrike.core.env import (
    windows_host,
    windows_key,
    windows_known_hosts,
    windows_user,
)
from redstrike.core.env import (
    windows_tools_dir as env_windows_tools_dir,
)
from redstrike.core.models import CallKind, CallSpec
from redstrike.runtime.beachhead import ExecutionPath, OperatorMode, StepPlan


def _ssh_binary() -> str:
    return os.environ.get("REDSTRIKE_SSH_BIN", "ssh")


def _windows_host() -> str:
    return windows_host() or "127.0.0.1"


def _windows_user() -> str:
    return windows_user() or "operator"


def _windows_ssh_key() -> str | None:
    return windows_key() or None


def _ssh_enabled() -> bool:
    return os.environ.get("REDSTRIKE_WINDOWS_SSH", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _quote_ps(arg: str) -> str:
    return "'" + arg.replace("'", "''") + "'"


def windows_tools_dir() -> str | None:
    """Where Windows tooling lives on the target host (first entry of a `;` list).

    ``REDSTRIKE_WINDOWS_TOOLS_DIR=C:\\Tools`` (multi-dir with ``;``) makes bare
    tool names resolve to that directory on the remote host, e.g. argv
    ``["Rubeus.exe", ...]`` becomes ``C:\\Tools\\Rubeus.exe`` inside the SSH
    command. `redstrike check` verifies presence there (remote probe) and
    `redstrike stage` pushes binaries into it.
    """
    raw = env_windows_tools_dir()
    if not raw:
        return None
    first = raw.split(";")[0].strip().rstrip("\\/")
    return first or None


def _resolve_remote_tool(name: str, tools_dir: str | None) -> str:
    """Prefix a bare .exe name with the tools dir (never non-executables/shells)."""
    if not tools_dir:
        return name
    if not name.lower().endswith(".exe"):
        return name
    if "\\" in name or "/" in name:
        return name
    return f"{tools_dir}\\{name}"


def wrap_argv_for_windows(argv: list[str]) -> list[str]:
    """Wrap a Windows-tool argv for execution on the remote target via OpenSSH."""
    if not argv:
        return argv
    if shutil.which(_ssh_binary()) is None:
        raise FileNotFoundError(
            f"REDSTRIKE windows-target SSH transport requires '{_ssh_binary()}' on PATH"
        )

    tool = _resolve_remote_tool(argv[0], windows_tools_dir())
    remote_ps = " ".join(_quote_ps(part) for part in [tool, *argv[1:]])
    remote_cmd = (
        f"powershell -NoProfile -ExecutionPolicy Bypass -Command "
        f'"& {{ {remote_ps} }}; exit $LASTEXITCODE"'
    )

    ssh_argv = [_ssh_binary()]
    key = _windows_ssh_key()
    if key:
        ssh_argv.extend(["-i", key])
    # Host identity: pin with REDSTRIKE_WINDOWS_KNOWN_HOSTS for a strict check;
    # otherwise accept-new (TOFU) as before.
    known_hosts = windows_known_hosts()
    if known_hosts:
        ssh_argv.extend(
            ["-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}"]
        )
    else:
        ssh_argv.extend(["-o", "StrictHostKeyChecking=accept-new"])
    ssh_argv.extend(
        [
            "-o",
            "BatchMode=yes",
            f"{_windows_user()}@{_windows_host()}",
            remote_cmd,
        ]
    )
    return ssh_argv


def argv_for_plan(plan: StepPlan) -> list[str] | CallSpec:
    """Return argv or CallSpec to run locally, via C2 implant, or SSH-wrapped.

    Operator modes:
    - linux: bash scripts keep windows-exec; typed intents SSH → PowerShell on the windows target
    - windows: already on the domain-joined host — never SSH wrap
    - c2: dispatches directly via C2 CallSpec
    """
    if plan.call_spec is not None and plan.call_spec.kind is CallKind.HTTP:
        # HTTP specs are dispatched by the runner; their "argv" is only a
        # display form (["http", METHOD, url]) and must never be exec'd.
        return plan.call_spec
    if plan.call_spec is not None and plan.path is ExecutionPath.C2_IMPLANT:
        return plan.call_spec
    if not plan.argv:
        return plan.call_spec if plan.call_spec is not None else plan.argv
    if plan.operator is OperatorMode.WINDOWS or plan.operator is OperatorMode.C2:
        return plan.call_spec if plan.call_spec is not None else plan.argv
    if plan.mechanism == "local-windows":
        return plan.argv
    if plan.path is not ExecutionPath.WINDOWS:
        return plan.call_spec if plan.call_spec is not None else plan.argv
    if not _ssh_enabled():
        return plan.argv
    if plan.mechanism == "windows-exec":
        return plan.argv
    if plan.mechanism.startswith("intent:") or plan.mechanism == "typed":
        return wrap_argv_for_windows(plan.argv)
    return plan.argv
