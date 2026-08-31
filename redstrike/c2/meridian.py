from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

from redstrike.c2.base import BaseC2Client
from redstrike.core.models import C2Backend, C2Session, CommandResult
from redstrike.core.runner import decode_captured, redact_argv


class MeridianClient(BaseC2Client):
    """Client adapter for Meridian C2, verified against the operator CLI.

    Contract (verified live against C2Stack's meridian container):
      * the operator surface is an in-process CLI, not a REST API;
      * `meridian sessions --json` -> JSON array of session objects;
      * `meridian exec --json <session> -- <command...>` queues a builtin exec
        task and returns {"queued": <task_id>, "session_id": ...};
      * `meridian results --json` -> JSON array of results with base64 stdout;
      * commands are asynchronous (beacon interval), so `shell()` polls results.
      * execute-assembly / psexec are not implemented by the meridian backend
        (built-in modules: exec/download/upload/sleep/exit) -> rejected.

    The CLI is usually reached inside the C2Stack container, configure
    ``command="docker exec -i docker-meridian-1 meridian"`` (as a list).
    """

    def __init__(
        self,
        endpoint: str = "meridian",
        api_key: str | None = None,
        timeout_seconds: int = 60,
        command: list[str] | str | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key or os.environ.get("MERIDIAN_API_KEY")
        self.timeout_seconds = timeout_seconds
        if command is None:
            self.command: list[str] = [endpoint] if endpoint not in ("", None) else ["meridian"]
        elif isinstance(command, str):
            self.command = command.split()
        else:
            self.command = command

    def _run_cli(self, argv: list[str], timeout: int) -> tuple[int, bytes, bytes]:
        try:
            completed = subprocess.run(
                self.command + argv,
                shell=False,
                check=False,
                capture_output=True,
                timeout=timeout,
            )
            return completed.returncode, completed.stdout, completed.stderr
        except FileNotFoundError:
            if self.command and "docker" in self.command[0]:
                msg = b"docker CLI not found on PATH (required to reach the meridian container)."
            else:
                msg = b"meridian not found on PATH. Point MeridianClient at the C2Stack CLI."
            return 1, b"", msg

    def _cli_json(self, argv: list[str], timeout: int) -> Any | None:
        rc, out, _err = self._run_cli(argv, timeout)
        if rc != 0:
            return None
        try:
            return json.loads(decode_captured(out))
        except ValueError:
            return None

    # ------------------------------------------------------------- interface
    def list_sessions(self) -> list[C2Session]:
        data = self._cli_json(["sessions", "--json"], 30)
        sessions: list[C2Session] = []
        for item in data if isinstance(data, list) else []:
            last_seen = datetime.now(timezone.utc)
            ts = item.get("last_seen")
            if isinstance(ts, (int, float)) and ts > 0:
                last_seen = datetime.fromtimestamp(ts, tz=timezone.utc)
            ips = item.get("ips") or []
            remote = ips[0] if isinstance(ips, list) and ips else None
            sessions.append(
                C2Session(
                    id=str(item.get("id") or ""),
                    backend=C2Backend.MERIDIAN,
                    hostname=item.get("hostname", "unknown"),
                    username=item.get("user") or item.get("uid") or "unknown",
                    os=item.get("os", "windows"),
                    arch=item.get("arch", "amd64"),
                    transport=item.get("listener") or item.get("transport") or "http",
                    last_seen=last_seen,
                    is_alive=bool(item.get("alive", True)),
                    remote_address=remote,
                )
            )
        return sessions

    def _exec(self, session_id: str, command: str, timeout_seconds: int) -> CommandResult:
        display_cmd = self.command + ["exec", "--json", session_id, "--", command]
        started = time.monotonic()

        try:
            rc, out, err = self._run_cli(
                ["exec", "--json", session_id, "--", command], timeout_seconds + 10
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
        if rc != 0:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=rc,
                stdout=decode_captured(out),
                stderr=decode_captured(err),
                duration_seconds=time.monotonic() - started,
            )

        task_id: str | None = None
        parsed: dict[str, Any] | None = None
        try:
            parsed = json.loads(decode_captured(out))
            task_id = parsed.get("queued") if isinstance(parsed, dict) else None
        except ValueError:
            pass
        if isinstance(parsed, dict) and parsed.get("error"):
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr=str(parsed["error"]),
                duration_seconds=time.monotonic() - started,
            )
        if not task_id:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=rc,
                stdout=decode_captured(out),
                stderr=decode_captured(err),
                duration_seconds=time.monotonic() - started,
            )

        deadline = started + timeout_seconds
        while time.monotonic() < deadline:
            rows = self._cli_json(["results", "--json"], 30)
            for row in rows if isinstance(rows, list) else []:
                if row.get("task_id") == task_id:
                    return CommandResult(
                        command=redact_argv(display_cmd),
                        return_code=int(row.get("exit_code") or 0) if row.get("status") != "error" else 1,
                        stdout=self._decode_out(row.get("stdout_b64")),
                        stderr=self._decode_out(row.get("stderr_b64")),
                        duration_seconds=time.monotonic() - started,
                    )
            time.sleep(3)
        return CommandResult(
            command=redact_argv(display_cmd),
            return_code=124,
            stdout="",
            stderr=f"task {task_id} did not complete within {timeout_seconds}s (beacon interval)",
            duration_seconds=time.monotonic() - started,
            timed_out=True,
        )

    @staticmethod
    def _decode_out(b64: str | None) -> str:
        if not b64:
            return ""
        try:
            return base64.b64decode(b64).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return ""

    def shell(
        self,
        session_id: str,
        command: str,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        return self._exec(session_id, command, timeout_seconds)

    def execute_assembly(
        self,
        session_id: str,
        assembly: str,
        args: list[str] | None = None,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        return CommandResult(
            command=redact_argv(["meridian", "execute-assembly", session_id, assembly] + (args or [])),
            return_code=2,
            stdout="",
            stderr=(
                "meridian backend has no execute-assembly module (built-in modules are "
                "exec/download/upload/sleep/exit). Use builtin/exec or a different backend."
            ),
            duration_seconds=0.0,
        )

    def psexec(
        self,
        session_id: str,
        target: str,
        service_name: str,
        bin_path: str,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        return CommandResult(
            command=redact_argv(["meridian", "psexec", session_id, target]),
            return_code=2,
            stdout="",
            stderr=(
                "meridian backend has no psexec lateral-movement module; "
                "queue a builtin/exec task with a crafted command instead."
            ),
            duration_seconds=0.0,
        )
