from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from redstrike.c2.base import BaseC2Client
from redstrike.core.models import C2Backend, C2Session, CommandResult
from redstrike.core.runner import redact_argv

_DEFAULT_TIMEOUT = 30
_POLL_INTERVAL = 3
_AUTH_GRACE = 60


class MythicClient(BaseC2Client):
    """Client adapter for Mythic C2 via the REST webhook API.

    Contract (verified live against C2Stack's mythic_server v3.4.0.61; tasking
    shapes re-verified against C2Stack's live command sweep, 2026-10-04 —
    see C2Stack Doc/internal/CAPABILITY-MATRIX.md §1.6):
      * The server exposes a Gin HTTP REST API on port 17443 (host-published
        7443, no TLS, no Hasura/GraphQL container in the C2Stack deployment).
      * Authentication: ``POST /auth`` with ``{"username","password"}`` returns
        ``{"access_token": "<JWT>", "refresh_token": "..."}``.  The JWT is sent
        as ``Authorization: Bearer <token>``.  A non-expiring API token can be
        generated via ``POST /api/v1.4/generate_apitoken_webhook`` and sent as
        ``apitoken: <token>`` instead.
      * Listing callbacks: the REST API has **no** list-callbacks endpoint, so
        the adapter queries the ``callback`` table directly through the Mythic
        Postgres container via ``psql`` inside ``docker exec``.  Sessions are
        keyed by the ``callback.id`` column — the same id the C2Stack portal
        tasks (``display_id`` currently mirrors it).
      * Creating a task: ``POST /api/v1.4/create_task_webhook`` with
        ``{"input": {"command": "<cmd>", "params": "<param string>",
        "callback_id": <int>}}`` -> ``{"status":"success","id":<taskID>}``.
        ``shell`` is an ALIAS command: ``params`` is the RAW command line,
        never JSON.
      * File-typed command params (``assembly_file`` etc.) need a Mythic
        ``agent_file_id`` — upload the bytes first via the multipart
        ``task_upload_file_webhook`` — plus ``parameter_group_name`` set to
        the uploaded-file group ("New Assembly").
      * Polling task results: no dedicated REST endpoint, so the adapter
        queries the ``task`` and ``response`` tables via the same psql path
        (``task.stdout`` never carries agent output in this stack).
      * Tasks are asynchronous (agent beacon interval); ``shell()`` polls until
        the task is completed or the timeout expires.
    """

    def __init__(
        self,
        endpoint: str = "http://127.0.0.1:7443",
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        postgres_container: str = "c2stack-mythic_postgres-1",
        postgres_db: str = "mythic_db",
        postgres_user: str = "mythic_user",
        timeout_seconds: int = 60,
        command: list[str] | str | None = None,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key or os.environ.get("MYTHIC_API_KEY")
        self.username = username or os.environ.get("MYTHIC_USERNAME", "mythic_admin")
        self.password = password or os.environ.get("MYTHIC_PASSWORD", "mythic")
        self.postgres_container = postgres_container
        self.postgres_db = postgres_db
        self.postgres_user = postgres_user
        self.timeout_seconds = timeout_seconds
        self._jwt: str | None = None
        self._jwt_expires: float = 0.0

    # ------------------------------------------------------------------ auth
    def _ensure_auth(self) -> str | None:
        """Return a valid auth header value, authenticating if needed."""
        if self.api_key:
            return self.api_key
        if self._jwt and time.monotonic() < self._jwt_expires:
            return self._jwt
        return self._login()

    def _login(self) -> str | None:
        body = json.dumps(
            {"username": self.username, "password": self.password}
        ).encode()
        resp = self._post("/auth", body, headers={"Content-Type": "application/json"})
        if resp is None:
            return None
        token = resp.get("access_token")
        if token:
            self._jwt = token
            self._jwt_expires = time.monotonic() + 3600 - _AUTH_GRACE
            return token
        return None

    def _auth_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        token = self._ensure_auth()
        if token:
            if self.api_key:
                headers["apitoken"] = token
            else:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    # ------------------------------------------------------------------ HTTP
    def _post(
        self, path: str, body: bytes, headers: dict[str, str] | None = None
    ) -> dict[str, Any] | None:
        url = self.endpoint + path
        req = Request(url, data=body, headers=headers or {}, method="POST")
        try:
            with urlopen(req, timeout=_DEFAULT_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except HTTPError as exc:
            return {"status": "error", "error": f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')[:200]}"}
        except (URLError, OSError, json.JSONDecodeError) as exc:
            return {"status": "error", "error": str(exc)}

    # ----------------------------------------------------------------- files
    def _upload_file(self, filename: str, content: bytes) -> str | None:
        """Stage operator bytes in Mythic and return the agent_file_id.

        Multipart form with a `file` field (the JSON body is rejected with
        "Missing file in form") — same contract C2Stack's portal uses for its
        /api/ops/mythic/upload staging endpoint.
        """
        import uuid

        token = self._ensure_auth()
        boundary = "----redstrike" + uuid.uuid4().hex
        crlf = "\r\n"
        body = (
            (
                f"--{boundary}{crlf}Content-Disposition: form-data; "
                f'name="file"; filename="{filename}"{crlf}'
                f"Content-Type: application/octet-stream{crlf}{crlf}"
            ).encode()
            + content
            + crlf.encode()
            + (f"--{boundary}--{crlf}").encode()
        )
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        if token:
            if self.api_key:
                headers["apitoken"] = token
            else:
                headers["Authorization"] = f"Bearer {token}"
        req = Request(
            self.endpoint + "/api/v1.4/task_upload_file_webhook",
            data=body, headers=headers, method="POST",
        )
        try:
            with urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except (HTTPError, URLError, OSError, json.JSONDecodeError):
            return None
        agent_file_id = data.get("agent_file_id")
        return str(agent_file_id) if agent_file_id else None

    # ------------------------------------------------------------------ psql
    def _psql(self, query: str) -> list[dict[str, Any]]:
        """Execute a psql query inside the Mythic postgres container."""
        import subprocess
        cmd = [
            "docker", "exec", self.postgres_container,
            "psql", "-U", self.postgres_user, "-d", self.postgres_db,
            "-A", "-F", "\t", "-c", query,
        ]
        try:
            completed = subprocess.run(
                cmd, shell=False, check=False, capture_output=True, timeout=_DEFAULT_TIMEOUT
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []
        raw = completed.stdout.decode("utf-8", errors="replace")
        if not raw.strip():
            return []
        # Unaligned psql without tuples-only (-t) emits a real header row and
        # a trailing "(N rows)" footer — the footer must be dropped and the
        # header used for keying (with -t there is NO header, so the first
        # data row would be mis-parsed as column names).
        lines = [
            ln for ln in raw.strip().split("\n")
            if ln.strip() and not ln.startswith("(")
        ]
        if not lines:
            return []
        cols = lines[0].split("\t")
        rows: list[dict[str, Any]] = []
        for line in lines[1:]:
            parts = line.split("\t")
            row: dict[str, Any] = {}
            for i, col in enumerate(cols):
                row[col] = parts[i] if i < len(parts) else ""
            rows.append(row)
        return rows

    # ------------------------------------------------------------- interface
    @staticmethod
    def _primary_ip(raw: str | None) -> str | None:
        """callback.ip is a Postgres jsonb array; prefer the IPv4 entry."""
        if not raw:
            return None
        if raw.startswith("["):
            try:
                ips = json.loads(raw)
            except ValueError:
                return raw
            if isinstance(ips, list):
                return next((ip for ip in ips if ip and ":" not in str(ip)), None)
        return raw

    def list_sessions(self) -> list[C2Session]:
        rows = self._psql(
            "SELECT id, host, \"user\", os, architecture, active, "
            "ip, external_ip, process_name, description, init_callback, "
            "last_checkin FROM callback ORDER BY id;"
        )
        sessions: list[C2Session] = []
        for row in rows:
            last_seen = datetime.now(timezone.utc)
            raw_ts = row.get("last_checkin") or row.get("init_callback")
            if raw_ts:
                try:
                    last_seen = datetime.strptime(raw_ts, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
                except ValueError:
                    try:
                        last_seen = datetime.strptime(raw_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    except ValueError:
                        pass
            remote = self._primary_ip(row.get("ip") or row.get("external_ip"))
            sessions.append(
                C2Session(
                    id=str(row.get("id") or row.get("display_id") or ""),
                    backend=C2Backend.MYTHIC,
                    hostname=row.get("host") or "unknown",
                    username=row.get("user") or "unknown",
                    os=row.get("os") or "unknown",
                    arch=row.get("architecture") or "amd64",
                    transport="http",
                    last_seen=last_seen,
                    is_alive=str(row.get("active")).lower() in ("true", "t"),
                    remote_address=remote,
                )
            )
        return sessions

    def _create_task(
        self, callback_id: int, command: str, params: str
    ) -> dict[str, Any] | None:
        body = json.dumps(
            {"input": {"command": command, "params": params, "callback_id": callback_id}}
        ).encode()
        return self._post("/api/v1.4/create_task_webhook", body, headers=self._auth_headers())

    def _poll_task(self, task_id: int, timeout: int) -> CommandResult:
        """Poll the task+response tables until the task is completed."""
        started = time.monotonic()
        deadline = started + timeout
        while time.monotonic() < deadline:
            rows = self._psql(
                f"SELECT t.status, t.completed, t.stdout, t.stderr, "
                f"array_agg(r.response ORDER BY r.sequence_number) as responses, "
                f"bool_or(r.is_error) as has_error "
                f"FROM task t LEFT JOIN response r ON r.task_id = t.id "
                f"WHERE t.id = {task_id} GROUP BY t.id;"
            )
            if rows:
                row = rows[0]
                status = str(row.get("status") or "").lower()
                completed = str(row.get("completed")).lower() in ("true", "t")
                if completed or status in ("success", "completed", "error"):
                    stdout = ""
                    stderr = str(row.get("stderr") or "")
                    raw_responses = row.get("responses")
                    if raw_responses and raw_responses != "{NULL}" and raw_responses != "{}":
                        parts = raw_responses.strip("{}").split(",")
                        decoded: list[str] = []
                        for part in parts:
                            part = part.strip()
                            if part and part != "NULL":
                                try:
                                    decoded.append(
                                        bytes.fromhex(part.lstrip("\\x")).decode("utf-8", errors="replace")
                                    )
                                except (ValueError, UnicodeDecodeError):
                                    pass
                        if decoded:
                            stdout = "\n".join(decoded)
                    if not stdout:
                        stdout = str(row.get("stdout") or "")
                    has_error = str(row.get("has_error")).lower() in ("true", "t")
                    return CommandResult(
                        command=redact_argv(["mythic", "task", str(task_id)]),
                        return_code=1 if (has_error or status == "error") else 0,
                        stdout=stdout,
                        stderr=stderr,
                        duration_seconds=time.monotonic() - started,
                    )
            time.sleep(_POLL_INTERVAL)
        return CommandResult(
            command=redact_argv(["mythic", "task", str(task_id)]),
            return_code=124,
            stdout="",
            stderr=f"task {task_id} did not complete within {timeout}s (beacon interval)",
            duration_seconds=time.monotonic() - started,
            timed_out=True,
        )

    def shell(
        self,
        session_id: str,
        command: str,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        display_cmd = ["mythic", "shell", session_id, command]
        started = time.monotonic()
        try:
            callback_id = int(session_id)
        except ValueError:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=2,
                stdout="",
                stderr=f"mythic callback_id must be an integer, got: {session_id}",
                duration_seconds=0.0,
            )
        # `shell` is an ALIAS command: params is the RAW command line, not
        # JSON (verified against C2Stack's live sweep — JSON params make the
        # agent treat the JSON blob as the command).
        result = self._create_task(callback_id, "shell", command)
        if result is None:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr="failed to create mythic task (connection error)",
                duration_seconds=time.monotonic() - started,
            )
        if result.get("status") != "success":
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr=result.get("error") or "task creation failed",
                duration_seconds=time.monotonic() - started,
            )
        task_id = result.get("id")
        if not task_id:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr="task created but no task ID returned",
                duration_seconds=time.monotonic() - started,
            )
        return self._poll_task(int(task_id), timeout_seconds)

    def execute_assembly(
        self,
        session_id: str,
        assembly: str,
        args: list[str] | None = None,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        display_cmd = ["mythic", "execute-assembly", session_id, assembly] + (args or [])
        started = time.monotonic()
        try:
            callback_id = int(session_id)
        except ValueError:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=2,
                stdout="",
                stderr=f"mythic callback_id must be an integer, got: {session_id}",
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
        # File-typed params need a Mythic agent_file_id: stage the assembly
        # via task_upload_file_webhook, then reference it from the uploaded-
        # file parameter group ("New Assembly") — C2Stack capability matrix
        # §1.6, live-swept 2026-10-04.
        try:
            with open(assembly, "rb") as fh:
                content = fh.read()
        except OSError as exc:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=2,
                stdout="",
                stderr=f"cannot read assembly {assembly}: {exc}",
                duration_seconds=0.0,
            )
        agent_file_id = self._upload_file(Path(assembly).name, content)
        if not agent_file_id:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr="failed to stage assembly in Mythic (task_upload_file_webhook)",
                duration_seconds=time.monotonic() - started,
            )
        params = json.dumps({
            "assembly_file": agent_file_id,
            "parameter_group_name": "New Assembly",
            "parameters": " ".join(args or []),
        })
        result = self._create_task(callback_id, "execute_assembly", params)
        if result is None:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr="failed to create mythic task (connection error)",
                duration_seconds=time.monotonic() - started,
            )
        if result.get("status") != "success":
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr=result.get("error") or "task creation failed",
                duration_seconds=time.monotonic() - started,
            )
        task_id = result.get("id")
        if not task_id:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr="task created but no task ID returned",
                duration_seconds=time.monotonic() - started,
            )
        return self._poll_task(int(task_id), timeout_seconds)

    def psexec(
        self,
        session_id: str,
        target: str,
        service_name: str,
        bin_path: str,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        display_cmd = ["mythic", "psexec", session_id, target, service_name]
        return CommandResult(
            command=redact_argv(display_cmd),
            return_code=2,
            stdout="",
            stderr=(
                "Apollo registers no `psexec` command (verified against the live "
                "payload type: lateral movement is jump_psexec / jump_wmi / "
                "jump_msbuild, whose param shapes are not yet verified headlessly "
                "— see C2Stack CAPABILITY-MATRIX §1.6). Use shell + sc.exe, "
                "wmiexecute, or a different backend for psexec-style movement."
            ),
            duration_seconds=0.0,
        )
