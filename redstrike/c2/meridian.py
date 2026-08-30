from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from redstrike.c2.base import BaseC2Client
from redstrike.core.models import C2Backend, C2Session, CommandResult
from redstrike.core.runner import redact_argv


class MeridianClient(BaseC2Client):
    """Client adapter for Meridian C2 (communicates via REST API over HTTP/DNS)."""

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:8080",
        api_key: str | None = None,
        timeout_seconds: int = 60,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key or os.environ.get("MERIDIAN_API_KEY")
        self.timeout_seconds = timeout_seconds

    def _http_request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> tuple[int, str]:
        url = f"{self.endpoint}/{path.lstrip('/')}"
        headers = {
            "User-Agent": "RedStrike-C2Adapter/1.0",
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status = response.status
                payload = response.read().decode("utf-8", errors="replace")
                return status, payload
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode("utf-8", errors="replace")
            return exc.code, payload
        except Exception as exc:  # noqa: BLE001
            return 503, str(exc)

    def list_sessions(self) -> list[C2Session]:
        """Query active sessions from the Meridian daemon."""
        status, payload = self._http_request("GET", "/api/sessions", timeout=10)
        if status != 200:
            return []

        try:
            data = json.loads(payload)
            sessions: list[C2Session] = []
            for item in data if isinstance(data, list) else data.get("sessions", []):
                sessions.append(
                    C2Session(
                        id=str(item.get("id") or ""),
                        backend=C2Backend.MERIDIAN,
                        hostname=item.get("hostname", "unknown"),
                        username=item.get("user") or item.get("username", "unknown"),
                        os=item.get("os", "windows"),
                        arch=item.get("arch", "amd64"),
                        transport=item.get("listener") or item.get("transport", "http"),
                        last_seen=datetime.now(timezone.utc),
                        is_alive=bool(item.get("alive", True)),
                        remote_address=item.get("remote_addr") or item.get("remote_address"),
                    )
                )
            return sessions
        except Exception:  # noqa: BLE001
            return []

    def task(
        self,
        session_id: str,
        module: str,
        action: str,
        params: dict[str, Any] | None = None,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        """Queue a task on a Meridian session and wait for result."""
        display_cmd = ["meridian", "task", session_id, module, action]
        if params:
            for k, v in params.items():
                display_cmd.extend([f"--{k}", str(v)])

        started = time.monotonic()
        body = {
            "session_id": session_id,
            "module": module,
            "action": action,
            "params": params or {},
        }

        status, payload = self._http_request("POST", f"/api/sessions/{session_id}/tasks", body=body, timeout=timeout_seconds)
        duration = time.monotonic() - started

        if status not in (200, 201, 202):
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr=f"Meridian task failed (HTTP {status}): {payload}",
                duration_seconds=duration,
            )

        try:
            result_data = json.loads(payload)
            stdout = result_data.get("output") or result_data.get("stdout") or payload
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=0 if result_data.get("status") != "error" else 1,
                stdout=str(stdout),
                stderr=str(result_data.get("error") or ""),
                duration_seconds=duration,
            )
        except Exception:  # noqa: BLE001
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=0,
                stdout=payload,
                stderr="",
                duration_seconds=duration,
            )

    def shell(
        self,
        session_id: str,
        command: str,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        return self.task(
            session_id=session_id,
            module="shell",
            action="exec",
            params={"command": command},
            timeout_seconds=timeout_seconds,
        )

    def execute_assembly(
        self,
        session_id: str,
        assembly: str,
        args: list[str] | None = None,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        return self.task(
            session_id=session_id,
            module="execute_assembly",
            action="run",
            params={"assembly": assembly, "args": args or []},
            timeout_seconds=timeout_seconds,
        )

    def psexec(
        self,
        session_id: str,
        target: str,
        service_name: str,
        bin_path: str,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        return self.task(
            session_id=session_id,
            module="psexec",
            action="run",
            params={"target": target, "service": service_name, "bin_path": bin_path},
            timeout_seconds=timeout_seconds,
        )
