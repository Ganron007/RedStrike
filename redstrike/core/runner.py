from __future__ import annotations

import os
import subprocess
import time
from shutil import which
from typing import Any

from redstrike.core.models import C2Backend, C2TaskType, CallKind, CallSpec, CommandResult

_UNIX_FALLBACKS = (
    "/usr/bin",
    "/bin",
    "/usr/local/bin",
    os.path.expanduser("~/.local/bin"),
)


def decode_captured(data: bytes | str | None) -> str:
    """Decode tool output without crashing the campaign.

    Mimikatz / Windows console tools often emit CP437/CP1252 (byte 0x83).
    ``text=True`` + UTF-8 locales raise UnicodeDecodeError and abort the phase.
    """
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if not data:
        return ""
    return data.decode("utf-8", errors="replace")


def resolve_executable(name: str) -> str:
    """Resolve argv[0] even when PATH is stripped (common in non-interactive SSH)."""
    found = which(name)
    if found:
        return found
    if os.path.isabs(name) and os.path.isfile(name):
        return name
    for directory in _UNIX_FALLBACKS:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    return name




class CommandRunner:
    def __init__(self, timeout_seconds: int = 300, c2_client: Any = None):
        self.timeout_seconds = timeout_seconds
        self.c2_client = c2_client

    def run(self, command: list[str] | CallSpec) -> CommandResult:
        if isinstance(command, CallSpec):
            return self.run_call_spec(command)
        return self._run_argv(command)

    def run_call_spec(self, spec: CallSpec) -> CommandResult:
        if spec.kind == CallKind.C2:
            return self._run_c2(spec)
        elif spec.kind == CallKind.HTTP:
            return self._run_http(spec)
        return self._run_argv(spec.argv)

    def _run_argv(self, argv: list[str]) -> CommandResult:
        if not argv:
            raise ValueError("Command cannot be empty")
        argv = [resolve_executable(argv[0])] + argv[1:]
        if which(argv[0]) is None and not os.path.isfile(argv[0]):
            raise FileNotFoundError(f"Required tool not found on PATH: {argv[0]}")

        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                shell=False,
                check=False,
                capture_output=True,
                timeout=self.timeout_seconds,
            )
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(argv),
                return_code=completed.returncode,
                stdout=decode_captured(completed.stdout),
                stderr=decode_captured(completed.stderr),
                duration_seconds=duration,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(argv),
                return_code=124,
                stdout=decode_captured(exc.stdout),
                stderr=decode_captured(exc.stderr),
                duration_seconds=duration,
                timed_out=True,
            )

    def _run_c2(self, spec: CallSpec) -> CommandResult:
        """Execute task via configured C2 client adapter."""
        from redstrike.c2 import get_c2_client

        client = self.c2_client
        if client is None:
            backend = spec.c2_backend or C2Backend.SLIVER
            client = get_c2_client(backend)

        if spec.c2_task_type == C2TaskType.EXECUTE_ASSEMBLY:
            return client.execute_assembly(
                session_id=spec.session_id or "",
                assembly=spec.assembly or "",
                args=spec.args,
                timeout_seconds=self.timeout_seconds,
            )
        elif spec.c2_task_type == C2TaskType.SHELL:
            return client.shell(
                session_id=spec.session_id or "",
                command=" ".join(spec.args),
                timeout_seconds=self.timeout_seconds,
            )
        elif spec.c2_task_type == C2TaskType.PSEXEC:
            target = spec.args[0] if len(spec.args) > 0 else ""
            service = spec.args[1] if len(spec.args) > 1 else "RedStrikeSvc"
            bin_path = spec.args[2] if len(spec.args) > 2 else ""
            return client.psexec(
                session_id=spec.session_id or "",
                target=target,
                service_name=service,
                bin_path=bin_path,
                timeout_seconds=self.timeout_seconds,
            )
        elif spec.c2_task_type == C2TaskType.LIST_SESSIONS:
            sessions = client.list_sessions()
            import json
            payload = json.dumps([s.model_dump(mode="json") for s in sessions], indent=2)
            return CommandResult(
                command=spec.to_display_command(),
                return_code=0,
                stdout=payload,
                stderr="",
                duration_seconds=0.01,
            )
        else:
            return client.shell(
                session_id=spec.session_id or "",
                command=" ".join(spec.args),
                timeout_seconds=self.timeout_seconds,
            )

    def _run_http(self, spec: CallSpec) -> CommandResult:
        import json
        import urllib.error
        import urllib.request

        started = time.monotonic()
        data = json.dumps(spec.body).encode("utf-8") if spec.body is not None else None
        req = urllib.request.Request(
            spec.url or "",
            data=data,
            headers=spec.headers,
            method=spec.method.upper(),
        )
        display_cmd = spec.to_display_command()

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                payload = resp.read().decode("utf-8", errors="replace")
                duration = time.monotonic() - started
                return CommandResult(
                    command=redact_argv(display_cmd),
                    return_code=0,
                    stdout=payload,
                    stderr="",
                    duration_seconds=duration,
                )
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode("utf-8", errors="replace")
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=exc.code,
                stdout="",
                stderr=f"HTTP Error {exc.code}: {payload}",
                duration_seconds=duration,
            )
        except Exception as exc:  # noqa: BLE001
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr=str(exc),
                duration_seconds=duration,
            )


def redact_argv(argv: list[str]) -> list[str]:
    redacted = list(argv)
    secret_flags = {"-p", "--password", "-H", "--hash", "-hashes", "--hashes"}
    for index, value in enumerate(redacted):
        if value in secret_flags:
            if index + 1 < len(redacted):
                redacted[index + 1] = "***REDACTED***"
            continue
        # Rubeus-style /password:SECRET /rc4:HASH /aes256:KEY
        for prefix in ("/password:", "/rc4:", "/aes256:", "/aes128:"):
            if value.lower().startswith(prefix):
                redacted[index] = prefix + "***REDACTED***"
        # impacket user:pass@host (non-empty host must look host-like, e.g. dns name or IP)
        user_part, sep, host = value.rpartition("@")
        if sep and ":" in user_part and (not host or "." in host or ":" in host):
            left, _pw = user_part.rsplit(":", 1)
            redacted[index] = f"{left}:***REDACTED***@{host}"
        # impacket domain/user:pass (e.g. GetUserSPNs.py)
        elif "/" in value and ":" in value and not value.startswith(("-", "/")):
            left, _pw = value.rsplit(":", 1)
            redacted[index] = f"{left}:***REDACTED***"

    # kerbrute passwordspray ... userlist password
    if len(redacted) >= 4 and "passwordspray" in redacted:
        # last argument is password
        redacted[-1] = "***REDACTED***"

    return redacted

