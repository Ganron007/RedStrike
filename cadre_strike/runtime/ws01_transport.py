from __future__ import annotations

import os
import shutil
from pathlib import Path

from cadre_strike.runtime.beachhead import ExecutionPath, StepPlan


def _ssh_binary() -> str:
    return os.environ.get("REDSTRIKE_SSH_BIN", "ssh")


def _ws01_host() -> str:
    return os.environ.get("REDSTRIKE_WS01_HOST", "192.168.77.62")


def _ws01_user() -> str:
    return os.environ.get("REDSTRIKE_WS01_USER", "analyst_t1")


def _ws01_ssh_key() -> str | None:
    explicit = os.environ.get("REDSTRIKE_WS01_SSH_KEY")
    if explicit:
        return explicit
    candidates = [
        Path.home() / ".ssh" / "cadre-ws01-key",
        Path(os.environ.get("USERPROFILE", "")) / ".ssh" / "cadre-ws01-key",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def _ssh_enabled() -> bool:
    return os.environ.get("REDSTRIKE_WS01_SSH", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _quote_ps(arg: str) -> str:
    return "'" + arg.replace("'", "''") + "'"


def wrap_argv_for_ws01(argv: list[str]) -> list[str]:
    """Wrap a local Windows-tool argv for execution on ws01 via OpenSSH."""
    if not argv:
        return argv
    if shutil.which(_ssh_binary()) is None:
        raise FileNotFoundError(
            f"REDSTRIKE ws01 SSH transport requires '{_ssh_binary()}' on PATH"
        )

    remote_ps = " ".join(_quote_ps(part) for part in argv)
    remote_cmd = (
        f"powershell -NoProfile -ExecutionPolicy Bypass -Command "
        f'"& {{ {remote_ps} }}; exit $LASTEXITCODE"'
    )

    ssh_argv = [_ssh_binary()]
    key = _ws01_ssh_key()
    if key:
        ssh_argv.extend(["-i", key])
    ssh_argv.extend(
        [
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{_ws01_user()}@{_ws01_host()}",
            remote_cmd,
        ]
    )
    return ssh_argv


def argv_for_plan(plan: StepPlan) -> list[str]:
    """Return argv to run locally (scripts) or SSH-wrapped (ws01 intents)."""
    if not plan.argv:
        return plan.argv
    if plan.path is not ExecutionPath.WS01:
        return plan.argv
    if not _ssh_enabled():
        return plan.argv
    if plan.mechanism == "ws01-exec":
        return plan.argv
    if plan.mechanism.startswith("intent:") or plan.mechanism == "typed":
        return wrap_argv_for_ws01(plan.argv)
    return plan.argv
