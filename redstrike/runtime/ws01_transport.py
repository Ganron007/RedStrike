from __future__ import annotations

import os
import shutil

from redstrike.core.models import CallSpec
from redstrike.runtime.beachhead import ExecutionPath, OperatorMode, StepPlan


def _ssh_binary() -> str:
    return os.environ.get("REDSTRIKE_SSH_BIN", "ssh")


def _ws01_host() -> str:
    return os.environ.get("REDSTRIKE_WS01_HOST", "127.0.0.1")


def _ws01_user() -> str:
    return os.environ.get("REDSTRIKE_WS01_USER", "operator")


def _ws01_ssh_key() -> str | None:
    explicit = os.environ.get("REDSTRIKE_WS01_SSH_KEY", "").strip()
    return explicit or None


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
    """Wrap a Windows-tool argv for execution on the remote beachhead via OpenSSH."""
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


def argv_for_plan(plan: StepPlan) -> list[str] | CallSpec:
    """Return argv or CallSpec to run locally, via C2 implant, or SSH-wrapped.

    Operator modes:
    - provisioning: bash scripts keep ws01-exec; typed intents SSH → PowerShell on ws01
    - ws01: already on the domain-joined host — never SSH wrap
    - c2: dispatches directly via C2 CallSpec
    """
    if plan.call_spec is not None and plan.path is ExecutionPath.C2_IMPLANT:
        return plan.call_spec
    if not plan.argv:
        return plan.call_spec if plan.call_spec is not None else plan.argv
    if plan.operator is OperatorMode.WS01 or plan.operator is OperatorMode.C2:
        return plan.call_spec if plan.call_spec is not None else plan.argv
    if plan.mechanism == "local-ws01":
        return plan.argv
    if plan.path is not ExecutionPath.WS01:
        return plan.call_spec if plan.call_spec is not None else plan.argv
    if not _ssh_enabled():
        return plan.argv
    if plan.mechanism == "ws01-exec":
        return plan.argv
    if plan.mechanism.startswith("intent:") or plan.mechanism == "typed":
        return wrap_argv_for_ws01(plan.argv)
    return plan.argv
