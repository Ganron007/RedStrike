from __future__ import annotations

import os
import re
import shlex
import signal
import subprocess
import time
from shutil import which
from typing import Any

from redstrike.core.env import unmsys
from redstrike.core.models import C2Backend, C2TaskType, CallKind, CallSpec, CommandResult

_UNIX_FALLBACKS = (
    "/usr/bin",
    "/bin",
    "/usr/local/bin",
    os.path.expanduser("~/.local/bin"),
)


def _kill_process_tree(proc: subprocess.Popen) -> None:
    """Kill a timed-out command AND its children (ssh/bash grandchildren can
    outlive the direct child, especially on Windows)."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
            check=False,
        )
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        proc.kill()
    except OSError:
        pass


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
    """Resolve argv[0] even when PATH is stripped (common in non-interactive SSH).

    Resolution order: PATH → absolute path → ``REDSTRIKE_LOCAL_TOOLS_DIR``
    entries (``;``-separated; the "point RedStrike at my tool directory" tier)
    → common unix fallbacks.
    """
    found = which(name)
    if found:
        return found
    if os.path.isabs(name) and os.path.isfile(name):
        return name
    for directory in local_tools_dirs():
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
        if os.name == "nt" and not name.lower().endswith(".exe"):
            exe_candidate = candidate + ".exe"
            if os.path.isfile(exe_candidate):
                return exe_candidate
    for directory in _UNIX_FALLBACKS:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate
    return name


def local_tools_dirs() -> list[str]:
    """Local tool directories from ``REDSTRIKE_LOCAL_TOOLS_DIR`` (``;``-separated)."""
    raw = os.environ.get("REDSTRIKE_LOCAL_TOOLS_DIR", "").strip()
    if not raw:
        return []
    return [part.strip().rstrip("\\/") for part in raw.split(";") if part.strip()]


def linux_remote_tools_dir() -> str | None:
    """Tool directory on the REMOTE/container Linux target (``REDSTRIKE_LINUX_TOOLS_DIR``).

    Bare tool names are resolved there, mirroring the Windows-side tools dir:
    point it at an isolated venv bin (``/opt/redstrike/venv/bin``) or a custom
    install prefix so RedStrike never depends on the target's system packages.
    Only takes effect for the container/ssh targets (local execution already
    has PATH plus ``REDSTRIKE_LOCAL_TOOLS_DIR`` fallback).
    """
    raw = unmsys(os.environ.get("REDSTRIKE_LINUX_TOOLS_DIR", "").strip())
    return raw.rstrip("/") or None


def _resolve_remote_name(name: str, tools_dir: str | None) -> str:
    """Prefix a bare tool name with the remote tools dir (explicit paths win)."""
    if not tools_dir:
        return name
    if "/" in name or "\\" in name:
        return name
    return f"{tools_dir}/{name}"




#: Basenames that are TRANSPORT shells, not tools — never container-wrapped.
_CONTAINER_SKIP_BASENAMES = {"ssh", "scp", "docker", "bash"}


def linux_container() -> str | None:
    """Operator-host container name for Linux tool execution.

    ``REDSTRIKE_LINUX_CONTAINER=c2stack-kali`` runs every Linux tool through
    ``docker exec -i <container> <argv...>`` — the C2Stack Kali operator
    container pattern (provision it with the manifest install recipes; it also
    sits on the C2Stack networks, so control ports are reachable internally).
    """
    name = os.environ.get("REDSTRIKE_LINUX_CONTAINER", "").strip()
    return name or None


def linux_ssh_base() -> list[str] | None:
    """SSH transport for a REMOTE Linux tool host (Kali VM / SSH-enabled container).

    ``REDSTRIKE_LINUX_SSH=user@host`` (± ``:port`` or ``REDSTRIKE_LINUX_SSH_PORT``,
    ``REDSTRIKE_LINUX_SSH_KEY``) — the mirror of the ws01 transport for the
    Linux side, so RedStrike can run on Windows and drive a dedicated Kali.
    Mutually exclusive with ``REDSTRIKE_LINUX_CONTAINER``.
    """
    target = unmsys(os.environ.get("REDSTRIKE_LINUX_SSH", "").strip())
    if not target:
        return None
    host = target
    port = os.environ.get("REDSTRIKE_LINUX_SSH_PORT", "").strip()
    if ":" in target and not target.startswith("["):
        host, _, maybe_port = target.rpartition(":")
        if maybe_port.isdigit():
            port = maybe_port
        else:
            host = target
    base = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=12"]
    # Host-key policy: a fresh box must not dead-end on the unknown-key prompt
    # (BatchMode would fail the first connection). Pin explicitly when the
    # operator provides known_hosts; otherwise trust-on-first-use.
    known_hosts = os.environ.get("REDSTRIKE_LINUX_SSH_KNOWN_HOSTS", "").strip()
    if known_hosts:
        base += ["-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}"]
    else:
        base += ["-o", "StrictHostKeyChecking=accept-new"]
    key = os.environ.get("REDSTRIKE_LINUX_SSH_KEY", "").strip()
    if key:
        base += ["-i", key]
    if port:
        base += ["-p", port]
    base.append(host)
    return base


class CommandRunner:
    def __init__(self, timeout_seconds: int = 300, c2_client: Any = None):
        self.timeout_seconds = timeout_seconds
        self.c2_client = c2_client

    def run(self, command: list[str] | CallSpec, *, timeout_seconds: int | None = None) -> CommandResult:
        if isinstance(command, CallSpec):
            return self.run_call_spec(command, timeout_seconds=timeout_seconds)
        return self._run_argv(command, timeout_seconds=timeout_seconds)

    def run_call_spec(self, spec: CallSpec, *, timeout_seconds: int | None = None) -> CommandResult:
        if spec.kind == CallKind.C2:
            return self._run_c2(spec, timeout_seconds=timeout_seconds)
        elif spec.kind == CallKind.HTTP:
            return self._run_http(spec, timeout_seconds=timeout_seconds)
        return self._run_argv(spec.argv, timeout_seconds=timeout_seconds)

    def _run_argv(self, argv: list[str], *, timeout_seconds: int | None = None) -> CommandResult:
        if not argv:
            raise ValueError("Command cannot be empty")
        timeout = timeout_seconds or self.timeout_seconds
        container = linux_container()
        ssh_base = linux_ssh_base()
        if container and ssh_base:
            raise ValueError(
                "both REDSTRIKE_LINUX_CONTAINER and REDSTRIKE_LINUX_SSH are set — "
                "pick exactly one Linux tool execution target"
            )
        base = os.path.basename(argv[0])
        display_cmd: list[str] | None = None
        if base in _CONTAINER_SKIP_BASENAMES:
            argv = [resolve_executable(argv[0])] + argv[1:]
            if which(argv[0]) is None and not os.path.isfile(argv[0]):
                raise FileNotFoundError(f"Required tool not found on PATH: {argv[0]}")
        elif container:
            # The tool lives INSIDE the container: resolve nothing locally,
            # just require the docker CLI.
            if which("docker") is None and not os.path.isfile("docker"):
                raise FileNotFoundError(
                    f"REDSTRIKE_LINUX_CONTAINER={container} is set but the docker CLI "
                    "was not found on PATH"
                )
            remote_dir = linux_remote_tools_dir()
            argv = ["docker", "exec", "-i", container, _resolve_remote_name(argv[0], remote_dir), *argv[1:]]
        elif ssh_base:
            # Remote Linux tool host: the whole invocation becomes ONE remote
            # shell command. Redact for DISPLAY and execute un-redacted (the
            # joined form would otherwise slip past argv-level redaction).
            if which("ssh") is None:
                raise FileNotFoundError(
                    f"REDSTRIKE_LINUX_SSH={ssh_base[-1]} is set but the ssh client "
                    "was not found on PATH"
                )
            remote_dir = linux_remote_tools_dir()
            tool = _resolve_remote_name(argv[0], remote_dir)
            remote_real = " ".join(shlex.quote(part) for part in [tool, *argv[1:]])
            remote_display = " ".join(
                shlex.quote(part) for part in [tool, *redact_argv(argv[1:])]
            )
            display_cmd = [*ssh_base, remote_display]
            argv = [*ssh_base, remote_real]
        else:
            argv = [resolve_executable(argv[0])] + argv[1:]
            if which(argv[0]) is None and not os.path.isfile(argv[0]):
                raise FileNotFoundError(f"Required tool not found on PATH: {argv[0]}")

        started = time.monotonic()
        popen_kwargs: dict[str, Any] = {
            "shell": False,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(argv, **popen_kwargs)
        try:
            out, err = proc.communicate(timeout=timeout)
            return CommandResult(
                command=display_cmd if display_cmd is not None else redact_argv(argv),
                return_code=proc.returncode,
                stdout=decode_captured(out),
                stderr=decode_captured(err),
                duration_seconds=time.monotonic() - started,
            )
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc)
            try:
                out, err = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                out, err = b"", b""
            return CommandResult(
                command=display_cmd if display_cmd is not None else redact_argv(argv),
                return_code=124,
                stdout=decode_captured(out),
                stderr=decode_captured(err),
                duration_seconds=time.monotonic() - started,
                timed_out=True,
            )

    def _run_c2(self, spec: CallSpec, *, timeout_seconds: int | None = None) -> CommandResult:
        """Execute task via configured C2 client adapter."""
        from redstrike.c2 import get_c2_client

        timeout = timeout_seconds or self.timeout_seconds
        client = self.c2_client
        if client is None:
            backend = spec.c2_backend or C2Backend.SLIVER
            client = get_c2_client(backend)

        if spec.c2_task_type == C2TaskType.EXECUTE_ASSEMBLY:
            return client.execute_assembly(
                session_id=spec.session_id or "",
                assembly=spec.assembly or "",
                args=spec.args,
                timeout_seconds=timeout,
            )
        elif spec.c2_task_type == C2TaskType.SHELL:
            return client.shell(
                session_id=spec.session_id or "",
                command=" ".join(spec.args),
                timeout_seconds=timeout,
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
                timeout_seconds=timeout,
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
                timeout_seconds=timeout,
            )

    def _run_http(self, spec: CallSpec, *, timeout_seconds: int | None = None) -> CommandResult:
        import json
        import urllib.error
        import urllib.request

        timeout = timeout_seconds or self.timeout_seconds
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
            with urllib.request.urlopen(req, timeout=timeout) as resp:
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


#: Flags whose FOLLOWING argument is secret material.
_SECRET_FLAGS = {
    "-p",
    "--password",
    "-H",
    "--hash",
    "-hashes",
    "--hashes",
    "--pfx-password",
    "-K",
    "--aesKey",
    "--aes-key",
    "--new-password",
    "--current-password",
    "--secret",
    "--token",
    "--api-key",
    "--key",
    "--prt",
    "--prt-sessionkey",
    "--client-secret",
    "--access-token",
    "--refresh-token",
    "--session-key",
}

#: Any flag whose NAME ends in a secret-ish word carries a secret value
#: (--pfx-password, --admin-pass, --api-token, ...).
_SECRET_FLAG_RE = re.compile(
    r"^-{1,2}[A-Za-z0-9_-]*(?:pass(?:word|wd)?|pwd|secret|token|key|hash(?:es)?)$",
    re.IGNORECASE,
)

#: Short flags that carry bearer material in specific tools (azurehound -j JWT,
#: -r refresh-token, roadrecon -c is a client id NOT a secret). Mask the value
#: only when it LOOKS like token material, so generic -j/-r usage is untouched.
_TOKENISH_FLAGS = {"-j", "-r"}
_TOKENISH_VALUE_RE = re.compile(r"^(eyJ[A-Za-z0-9._-]{20,}|0\.[A-Za-z0-9._-]{20,}|[A-Za-z0-9._-]{40,})$")

#: Rubeus/impacket inline secret prefixes (/password:X, /rc4:HASH, ...).
_INLINE_SECRET_PREFIXES = (
    "/password:",
    "/rc4:",
    "/aes256:",
    "/aes128:",
    "/des:",
)


def redact_argv(argv: list[str]) -> list[str]:
    redacted = list(argv)
    for index, value in enumerate(redacted):
        if value in _SECRET_FLAGS or _SECRET_FLAG_RE.match(value):
            if index + 1 < len(redacted):
                redacted[index + 1] = "***REDACTED***"
            continue
        if value in _TOKENISH_FLAGS and index + 1 < len(redacted):
            candidate = redacted[index + 1]
            if _TOKENISH_VALUE_RE.match(candidate):
                redacted[index + 1] = "***REDACTED***"
            continue
        # Rubeus-style /password:SECRET /rc4:HASH /aes256:KEY
        for prefix in _INLINE_SECRET_PREFIXES:
            if value.lower().startswith(prefix):
                redacted[index] = prefix + "***REDACTED***"
        # impacket user:pass@host (non-empty host must look host-like, e.g. dns name or IP)
        user_part, sep, host = value.rpartition("@")
        if sep and ":" in user_part and (not host or "." in host or ":" in host):
            left, _pw = user_part.rsplit(":", 1)
            redacted[index] = f"{left}:***REDACTED***@{host}"
        # impacket domain/user:pass (e.g. GetUserSPNs.py) — the colon must come
        # AFTER the last slash (a URL's scheme colon comes before it and must
        # never be redacted: https://graph.microsoft.com/v1.0/users).
        elif "/" in value and ":" in value and not value.startswith(("-", "/")):
            if value.rfind(":") > value.rfind("/"):
                left, _pw = value.rsplit(":", 1)
                redacted[index] = f"{left}:***REDACTED***"

    # kerbrute passwordspray ... userlist password
    if len(redacted) >= 4 and "passwordspray" in redacted:
        # last argument is password
        redacted[-1] = "***REDACTED***"

    return redacted

