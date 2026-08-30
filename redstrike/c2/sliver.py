from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from redstrike.c2.base import BaseC2Client
from redstrike.core.models import C2Backend, C2Session, CommandResult
from redstrike.core.runner import decode_captured, redact_argv


class SliverClient(BaseC2Client):
    """Client adapter for Sliver C2 (communicates via sliver-client CLI or RPC)."""

    def __init__(
        self,
        endpoint: str = "127.0.0.1:31337",
        config_path: str | Path | None = None,
        sliver_binary: str = "sliver-client",
        timeout_seconds: int = 120,
    ) -> None:
        self.endpoint = endpoint
        self.config_path = Path(config_path) if config_path else None
        self.sliver_binary = sliver_binary
        self.timeout_seconds = timeout_seconds

    def _build_base_cmd(self) -> list[str]:
        cmd = [self.sliver_binary]
        if self.config_path and self.config_path.exists():
            cmd.extend(["--config", str(self.config_path)])
        return cmd

    def list_sessions(self) -> list[C2Session]:
        """List active sessions from the Sliver teamserver."""
        cmd = self._build_base_cmd() + ["sessions", "--json"]
        if shutil.which(self.sliver_binary) is None and not os.path.isfile(self.sliver_binary):
            # In offline test or when sliver-client is not installed on path
            return []

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                check=False,
                timeout=15,
            )
            if res.returncode != 0 or not res.stdout:
                return []
            data = json.loads(decode_captured(res.stdout))
            sessions: list[C2Session] = []
            for item in data if isinstance(data, list) else [data]:
                sessions.append(
                    C2Session(
                        id=str(item.get("id") or item.get("ID") or ""),
                        backend=C2Backend.SLIVER,
                        hostname=item.get("hostname", "unknown"),
                        username=item.get("username", "unknown"),
                        os=item.get("os", "windows"),
                        arch=item.get("arch", "amd64"),
                        transport=item.get("transport", "http"),
                        last_seen=datetime.now(timezone.utc),
                        is_alive=bool(item.get("is_dead") is False or item.get("alive", True)),
                        remote_address=item.get("remote_address"),
                    )
                )
            return sessions
        except Exception:  # noqa: BLE001
            return []

    def execute_assembly(
        self,
        session_id: str,
        assembly: str,
        args: list[str] | None = None,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        """Execute a .NET binary in-memory inside the remote session context."""
        arg_list = args or []
        display_cmd = [self.sliver_binary, "execute-assembly", "-i", session_id, assembly] + arg_list
        started = time.monotonic()

        if shutil.which(self.sliver_binary) is None and not os.path.isfile(self.sliver_binary):
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr="sliver-client not found on PATH. Ensure C2Stack sliver-client is configured.",
                duration_seconds=duration,
            )

        cmd = self._build_base_cmd() + ["execute-assembly", "-i", session_id, assembly]
        if arg_list:
            cmd.extend(["--process-arguments", " ".join(arg_list)])

        try:
            completed = subprocess.run(
                cmd,
                shell=False,
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
            )
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=completed.returncode,
                stdout=decode_captured(completed.stdout),
                stderr=decode_captured(completed.stderr),
                duration_seconds=duration,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=124,
                stdout=decode_captured(exc.stdout),
                stderr=decode_captured(exc.stderr),
                duration_seconds=duration,
                timed_out=True,
            )

    def shell(
        self,
        session_id: str,
        command: str,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        """Execute a remote shell command inside the session context."""
        display_cmd = [self.sliver_binary, "shell", "-i", session_id, "-c", command]
        started = time.monotonic()

        if shutil.which(self.sliver_binary) is None and not os.path.isfile(self.sliver_binary):
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr="sliver-client not found on PATH.",
                duration_seconds=duration,
            )

        cmd = self._build_base_cmd() + ["shell", "-i", session_id, "-c", command]
        try:
            completed = subprocess.run(
                cmd,
                shell=False,
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
            )
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=completed.returncode,
                stdout=decode_captured(completed.stdout),
                stderr=decode_captured(completed.stderr),
                duration_seconds=duration,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - started
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=124,
                stdout=decode_captured(exc.stdout),
                stderr=decode_captured(exc.stderr),
                duration_seconds=duration,
                timed_out=True,
            )

    def psexec(
        self,
        session_id: str,
        target: str,
        service_name: str,
        bin_path: str,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        """PsExec lateral movement from the implant session."""
        display_cmd = [
            self.sliver_binary, "psexec", "-i", session_id,
            "-t", target, "-s", service_name, "-b", bin_path
        ]
        started = time.monotonic()
        if shutil.which(self.sliver_binary) is None and not os.path.isfile(self.sliver_binary):
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr="sliver-client not found on PATH.",
                duration_seconds=time.monotonic() - started,
            )

        cmd = self._build_base_cmd() + [
            "psexec", "-i", session_id,
            "-t", target, "-s", service_name, "-b", bin_path
        ]
        try:
            completed = subprocess.run(
                cmd,
                shell=False,
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
            )
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=completed.returncode,
                stdout=decode_captured(completed.stdout),
                stderr=decode_captured(completed.stderr),
                duration_seconds=time.monotonic() - started,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=124,
                stdout=decode_captured(exc.stdout),
                stderr=decode_captured(exc.stderr),
                duration_seconds=time.monotonic() - started,
                timed_out=True,
            )
