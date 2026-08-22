from __future__ import annotations

import os
import subprocess
import time
from shutil import which

from redstrike.core.models import CommandResult

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
    def __init__(self, timeout_seconds: int = 300):
        self.timeout_seconds = timeout_seconds

    def run(self, argv: list[str]) -> CommandResult:
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


def redact_argv(argv: list[str]) -> list[str]:
    redacted = list(argv)
    secret_flags = {"-p", "--password", "-H", "--hash", "-hashes", "--hashes"}
    for index, value in enumerate(redacted[:-1]):
        if value in secret_flags:
            redacted[index + 1] = "***REDACTED***"
            continue
        # Rubeus-style /password:SECRET /rc4:HASH
        for prefix in ("/password:", "/rc4:", "/aes256:", "/aes128:"):
            if value.lower().startswith(prefix):
                redacted[index] = prefix + "***REDACTED***"
        # impacket user:pass@host
        if "@" in value and ":" in value.split("@", 1)[0]:
            user_part, host = value.rsplit("@", 1)
            if ":" in user_part:
                left, _pw = user_part.rsplit(":", 1)
                redacted[index] = f"{left}:***REDACTED***@{host}"
    return redacted

