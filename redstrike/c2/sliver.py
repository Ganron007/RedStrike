from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from redstrike.c2.base import BaseC2Client
from redstrike.core.models import C2Backend, C2Session, CommandResult
from redstrike.core.runner import decode_captured, redact_argv

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_SPINNER_RE = re.compile(r"^[|/\\\-=]+\s*$")
_NO_RESULTS_RE = re.compile(r"^No (sessions|beacons) ", re.IGNORECASE)


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _column_starts(header: str) -> list[int]:
    """Column start offsets from a fixed-width header.

    Columns are left-aligned runs separated by 2+ spaces; tokens separated by
    a single space (e.g. "Process (PID)") belong to one column.
    """
    starts: list[int] = []
    prev_end = -2
    for m in re.finditer(r"\S+", header):
        gap = m.start() - (prev_end + 1)
        if gap > 1:
            starts.append(m.start())
        prev_end = m.end() - 1
    return starts


def _parse_table(text: str) -> list[dict[str, str]]:
    """Parse a fixed-width sliver console table (sessions/beacons) into rows."""
    lines = [_strip_ansi(ln.rstrip()) for ln in text.splitlines()]
    header_idx: int | None = None
    for i, ln in enumerate(lines):
        if re.match(r"^\s*ID\s+Name\s+", ln):
            header_idx = i
            break
    if header_idx is None:
        return []
    header = _strip_ansi(lines[header_idx])
    starts = _column_starts(header)
    header_tokens = [
        header[start: starts[idx + 1] if idx + 1 < len(starts) else len(header)].strip()
        for idx, start in enumerate(starts)
    ]
    rows: list[dict[str, str]] = []
    for ln in lines[header_idx + 1:]:
        if not ln.startswith((" ", "\t")):
            continue
        if not ln.strip() or _SPINNER_RE.match(ln.strip()) or _NO_RESULTS_RE.match(ln):
            continue
        if "=" in ln[:8]:
            continue
        row = {}
        for idx, col in enumerate(header_tokens):
            end = starts[idx + 1] if idx + 1 < len(starts) else len(ln)
            row[col] = ln[starts[idx]:end].strip()
        rows.append(row)
    return rows


def _session_from_row(row: dict[str, str]) -> C2Session | None:
    sid = row.get("ID", "").strip()
    if not sid or len(sid) < 4:
        return None
    os_arch = row.get("Operating System", "")
    os_name, _, arch = os_arch.partition("/")
    last_message = row.get("Last Message", "")
    last_seen = datetime.now(timezone.utc)
    m = re.search(r"([A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} UTC \d{4})", last_message)
    if m:
        try:
            last_seen = datetime.strptime(m.group(1), "%a %b %d %H:%M:%S UTC %Y").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            pass
    health = row.get("Health", "")
    return C2Session(
        id=sid,
        backend=C2Backend.SLIVER,
        hostname=row.get("Hostname", "unknown") or "unknown",
        username=row.get("Username", "unknown") or "unknown",
        os=os_name or row.get("Operating System", "linux"),
        arch=arch or "amd64",
        transport=row.get("Transport", "http"),
        last_seen=last_seen,
        is_alive="DEAD" not in health.upper() and health not in ("", "[OFFLINE]") or "ALIVE" in health.upper(),
        remote_address=row.get("Remote Address"),
    )


class SliverClient(BaseC2Client):
    """Client adapter for Sliver C2, verified against the v1.7.6 client CLI.

    Contract (verified live against C2Stack's sliver v1.7.6 container):
      * operator config is imported, not passed per-call (`import`, no `--config`);
      * headless listing runs the console with a script: `console --rc <file>`
        where the file contains `sessions` / `beacons` / `exit`; output is a
        fixed-width table (no `--json` in the 1.7.6 console);
      * remote execution runs the `implant` subtree with the session selected
        via `implant -s <id>`: `implant -s <id> execute <path> [-- args...]`,
        `implant -s <id> execute-assembly <assembly> [--process-arguments ...]`;
      * `shell` has no headless one-shot (interactive tunnel, `--no-pty` /
        `--shell-path` only) -> mapped to `execute` with the session shell;
      * `psexec` requires the operator console TTY (bubbletea confirmation
        prompt fails on closed TTY) -> rejected with a diagnostic.
    """

    def __init__(
        self,
        endpoint: str = "127.0.0.1:31337",
        config_path: str | Path | None = None,
        sliver_binary: str = "sliver-client",
        timeout_seconds: int = 120,
        shell_path: str | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.config_path = Path(config_path) if config_path else None
        self.sliver_binary = sliver_binary
        self.timeout_seconds = timeout_seconds
        self.shell_path = shell_path
        self._session_os: dict[str, str] = {}
        self._imported = False

    # ------------------------------------------------------------------ infra
    def _missing_binary(self) -> str | None:
        if shutil.which(self.sliver_binary) is None and not os.path.isfile(self.sliver_binary):
            return (
                "sliver-client not found on PATH. Ensure C2Stack sliver-client "
                "is configured (v1.7.6 contract)."
            )
        return None

    def _run(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        completed = subprocess.run(
            argv,
            shell=False,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
        return (
            completed.returncode,
            decode_captured(completed.stdout),
            decode_captured(completed.stderr),
        )

    def _ensure_import(self) -> str | None:
        if self._imported:
            return None
        missing = self._missing_binary()
        if missing:
            return missing
        if self.config_path and self.config_path.exists():
            _, out, err = self._run([self.sliver_binary, "import", str(self.config_path)], 30)
            if "Config imported" not in out and "error" in err.lower() and "already" not in err.lower():
                return f"sliver-client import failed: {err or out}".strip()
        self._imported = True
        return None

    # ------------------------------------------------------------- interface
    def list_sessions(self) -> list[C2Session]:
        err = self._ensure_import()
        if err:
            return []
        rc_file = Path(tempfile.gettempdir()) / f"redstrike-sliver-rc-{os.getpid()}.txt"
        rc_file.write_text("sessions\nbeacons\nexit\n", encoding="utf-8")
        try:
            _, out, _ = self._run(
                [self.sliver_binary, "console", "--rc", str(rc_file)], self.timeout_seconds
            )
        finally:
            try:
                rc_file.unlink(missing_ok=True)
            except OSError:
                pass

        sessions: list[C2Session] = []
        for row in _parse_table(out):
            session = _session_from_row(row)
            if session:
                self._session_os[session.id] = session.os
                sessions.append(session)
        return sessions

    def execute_assembly(
        self,
        session_id: str,
        assembly: str,
        args: list[str] | None = None,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        display_cmd = [
            self.sliver_binary, "implant", "-s", session_id, "execute-assembly", assembly
        ] + (args or [])
        started = time.monotonic()
        missing = self._missing_binary()
        if missing:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr=missing,
                duration_seconds=time.monotonic() - started,
            )
        if not assembly:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=2,
                stdout="",
                stderr="no assembly path provided",
                duration_seconds=time.monotonic() - started,
            )
        cmd = [self.sliver_binary, "implant", "-s", session_id, "execute-assembly", assembly]
        if args:
            cmd.extend(["--process-arguments", " ".join(args)])
        cmd.extend(["-t", str(timeout_seconds)])
        try:
            rc, out, err = self._run(cmd, timeout_seconds + 10)
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=rc,
                stdout=_output_block(out),
                stderr=err,
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

    def shell(
        self,
        session_id: str,
        command: str,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        os_name = self.shell_path and "" or self._session_os.get(session_id, "")
        if self.shell_path:
            shell_path = self.shell_path
            prefix: list[str] = ["-c", command]
        elif "windows" in os_name.lower():
            shell_path = "cmd.exe"
            prefix = ["/C", command]
        else:
            shell_path = "/bin/sh"
            prefix = ["-c", command]
        display_cmd = [
            self.sliver_binary, "implant", "-s", session_id,
            "execute", shell_path, "--", *prefix,
        ]
        return self._execute(session_id, shell_path, prefix, display_cmd, timeout_seconds)

    def _execute(
        self,
        session_id: str,
        shell_path: str,
        argv: list[str],
        display_cmd: list[str],
        timeout_seconds: int,
    ) -> CommandResult:
        started = time.monotonic()
        missing = self._missing_binary()
        if missing:
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=1,
                stdout="",
                stderr=missing,
                duration_seconds=time.monotonic() - started,
            )
        cmd = [
            self.sliver_binary, "implant", "-s", session_id,
            "execute", shell_path, "--", *argv,
        ]
        cmd.extend(["-t", str(timeout_seconds)])
        try:
            rc, out, err = self._run(cmd, timeout_seconds + 10)
            return CommandResult(
                command=redact_argv(display_cmd),
                return_code=rc,
                stdout=_output_block(out),
                stderr=err,
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

    def psexec(
        self,
        session_id: str,
        target: str,
        service_name: str,
        bin_path: str,
        timeout_seconds: int = 120,
    ) -> CommandResult:
        display_cmd = [
            self.sliver_binary, "implant", "-s", session_id,
            "psexec", "-s", service_name,
            *(["-b", bin_path] if bin_path else []),
            target,
        ]
        return CommandResult(
            command=redact_argv(display_cmd),
            return_code=2,
            stdout="",
            stderr=(
                "sliver v1.7.6 psexec requires the interactive operator console: the "
                "service-confirmation prompt (bubbletea) cannot be answered on a closed "
                "TTY, so headless automation cannot drive it. Create the service profile "
                "and run psexec from `sliver-client console` manually."
            ),
            duration_seconds=0.0,
        )


def _output_block(text: str) -> str:
    """Extract the captured-output block from `implant execute* -- stdout`."""
    found = False
    block: list[str] = []
    for ln in text.splitlines():
        stripped = _strip_ansi(ln)
        if stripped.startswith("[*] Output:"):
            found = True
            rest = stripped.split(":", 1)[1] if ":" in stripped else ""
            if rest.strip():
                block.append(rest)
            continue
        if found:
            if stripped.startswith(("[*] ", "[!] ")):
                break
            block.append(stripped)
    return "\n".join(block)
