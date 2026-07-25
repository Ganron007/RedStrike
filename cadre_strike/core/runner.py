from __future__ import annotations

import subprocess
import time
from shutil import which

from cadre_strike.core.models import CommandResult


class CommandRunner:
    def __init__(self, timeout_seconds: int = 300):
        self.timeout_seconds = timeout_seconds

    def run(self, argv: list[str]) -> CommandResult:
        if not argv:
            raise ValueError("Command cannot be empty")
        if which(argv[0]) is None:
            raise FileNotFoundError(f"Required tool not found on PATH: {argv[0]}")

        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(argv),
                return_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                duration_seconds=duration,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(argv),
                return_code=124,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
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

