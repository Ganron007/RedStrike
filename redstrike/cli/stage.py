"""`redstrike stage` — provision Windows tooling onto the beachhead.

Three tiers for Windows-side tools (rubeus, mimikatz, sharphound, SharpSCCM, …):

1. **manual install** — operator stages the file themselves;
2. **tools-dir autodiscovery** — `REDSTRIKE_WINDOWS_TOOLS_DIR` (alias `REDSTRIKE_WS01_TOOLS_DIR`) let RedStrike
   resolve bare tool names on the remote host (see ws01_transport);
3. **download via setup** — this command: pinned upstream releases
   (`source_url` + `sha256` in the tool manifest) are fetched, hash-verified,
   optionally extracted from their zip, and pushed to the beachhead with scp.

Pins are enforced when present; operator-supplied files get their hash
recorded (never silently trusted as a "known" binary).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from redstrike.core.env import (
    windows_host,
    windows_key,
    windows_tools_dir,
    windows_user,
)
from redstrike.core.manifest import TOOL_MANIFEST, ToolSpec, stage_display_name

_DEFAULT_TMP = Path(tempfile.gettempdir())


def _tool(name: str) -> ToolSpec:
    for spec in TOOL_MANIFEST:
        if spec.name == name:
            return spec
    known = ", ".join(s.name for s in TOOL_MANIFEST if s.platform == "windows")
    raise KeyError(f"unknown tool '{name}'; windows-side tools: {known}")


def _env(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def _ws01_settings(args: argparse.Namespace) -> dict[str, str | None]:
    host = args.host or windows_host()
    user = args.user or windows_user() or "operator"
    key = args.key or windows_key()
    return {"host": host, "user": user, "key": key}


def _target_dir(args: argparse.Namespace) -> str:
    if args.dir:
        return args.dir.rstrip("\\/")
    raw = windows_tools_dir()
    if raw:
        return raw.split(";")[0].strip().rstrip("\\/")
    raise SystemExit(
        "no tools directory: pass --dir 'C:\\Tools' or set "
        "REDSTRIKE_WINDOWS_TOOLS_DIR (used by stage AND by run-time tool resolution)"
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fetch(url: str) -> bytes:  # pragma: no cover - thin network helper
    import urllib.request

    with urllib.request.urlopen(url, timeout=180) as resp:
        return resp.read()


def _extract_member(payload: bytes, member: str, *, url: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        try:
            return archive.read(member)
        except KeyError as exc:
            names = ", ".join(archive.namelist()[:12])
            raise KeyError(f"'{member}' not in {url} (members: {names}…)") from exc


def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _ensure_remote_dir(settings: dict[str, str | None], directory: str) -> None:
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=12"]
    if settings["key"]:
        ssh += ["-i", settings["key"]]
    remote = (
        "powershell -NoProfile -Command "
        f"\"New-Item -ItemType Directory -Force -Path '{directory}' | Out-Null\""
    )
    done = _run([*ssh, f"{settings['user']}@{settings['host']}", remote], timeout=30)
    if done.returncode != 0:
        raise RuntimeError(f"could not create {directory} on ws01: {done.stderr.strip()[:200]}")


def _push(settings: dict[str, str | None], local_path: Path, directory: str, stage_name: str) -> str:
    if shutil.which("scp") is None:
        raise RuntimeError("scp not found on PATH (OpenSSH client required)")
    remote_posix = f"{directory.replace(chr(92), '/')}/{stage_name}"
    scp = ["scp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=12"]
    if settings["key"]:
        scp += ["-i", settings["key"]]
    done = _run([*scp, str(local_path), f"{settings['user']}@{settings['host']}:{remote_posix}"], timeout=300)
    if done.returncode != 0:
        raise RuntimeError(f"scp failed: {done.stderr.strip()[:300]}")
    return f"{directory}\\{stage_name}"


def _plan(args: argparse.Namespace) -> int:
    directory = args.dir or (windows_tools_dir() or "(set REDSTRIKE_WINDOWS_TOOLS_DIR)").split(";")[0]
    rows: list[dict[str, Any]] = []
    for spec in TOOL_MANIFEST:
        if spec.platform not in ("windows", "both"):
            continue
        display = stage_display_name(spec)
        rows.append(
            {
                "tool": spec.name,
                "stage_name": display,
                "pinned": bool(spec.source_url and spec.sha256),
                "source_url": spec.source_url,
                "sha256": spec.sha256,
                "install": spec.install,
                "target": f"{directory}\\{display}" if directory else None,
            }
        )
    if args.json:
        print(json.dumps({"tools_dir": directory, "windows_tools": rows}, indent=2))
        return 0
    print(f"Windows beachhead tooling (target: {directory})")
    for row in rows:
        pin = "pinned" if row["pinned"] else "operator-supplied"
        print(f"  {row['tool']:12s} {row['stage_name']:16s} {pin:18s} {row['install']}")
    print()
    print("  download:  redstrike stage --tool mimikatz --download")
    print("  local file: redstrike stage --tool rubeus --file C:\\build\\Rubeus.exe")
    print("  pick up at run time: REDSTRIKE_WINDOWS_TOOLS_DIR lets intents resolve bare names")
    return 0


def _stage_one(args: argparse.Namespace) -> int:
    spec = _tool(args.tool)
    if spec.platform not in ("windows", "both"):
        print(f"'{spec.name}' is {spec.platform}-side; the Windows staging path does not apply.", file=sys.stderr)
        return 2
    directory = _target_dir(args)
    stage_name = args.name or stage_display_name(spec)

    payload: bytes
    artifact_verified = False
    artifact_sha: str | None = None
    note: str | None = None
    if args.file:
        source_path = Path(args.file)
        if not source_path.is_file():
            print(f"file not found: {source_path}", file=sys.stderr)
            return 1
        payload = source_path.read_bytes()
        digest = _sha256(payload)
        # Pin semantics: sha256 covers the DOWNLOADED artifact. Archive tools
        # (source_member set — mimikatz, SharpHound) verify at download time;
        # a --file input is the EXTRACTED binary, so the archive pin does not
        # apply to it (hash recorded instead).
        if spec.sha256 and not spec.source_member:
            if digest != spec.sha256:
                print(
                    f"sha256 MISMATCH for {spec.name}: file has {digest}, pinned "
                    f"{spec.sha256} — refusing to stage.",
                    file=sys.stderr,
                )
                return 2
            artifact_verified = True
        elif spec.sha256 and spec.source_member:
            note = (
                f"'{spec.name}' pin covers the upstream archive "
                f"({spec.source_url.rsplit('/', 1)[-1]}); staged file hash RECORDED: {digest}"
            )
        else:
            note = (
                f"'{spec.name}' has no upstream pin; staging hash RECORDED: {digest} "
                "(not claimed as verified)"
            )
        if note and not args.json:
            print(f"note: {note}")
    elif args.download:
        if not spec.source_url:
            print(
                f"'{spec.name}' has no pinned upstream artifact "
                f"(upstream is source-only or unpinned) — use --file.\n{spec.hint}",
                file=sys.stderr,
            )
            return 2
        if not args.json:
            print(f"fetching {spec.source_url}")
        artifact = _fetch(spec.source_url)
        if spec.sha256:
            artifact_sha = _sha256(artifact)
            if artifact_sha != spec.sha256:
                print(
                    f"sha256 MISMATCH for {spec.name}: got {artifact_sha}, "
                    f"pinned {spec.sha256} — refusing to stage.",
                    file=sys.stderr,
                )
                return 2
            artifact_verified = True
            if not args.json:
                print(f"artifact sha256 verified: {artifact_sha}")
        payload = (
            _extract_member(artifact, spec.source_member, url=spec.source_url)
            if spec.source_member
            else artifact
        )
    else:
        print("pass --download (pinned upstream) or --file <path>", file=sys.stderr)
        return 2

    digest = _sha256(payload)

    settings = _ws01_settings(args)
    if not settings["host"]:
        print(
            "no beachhead configured: set REDSTRIKE_WINDOWS_HOST/USER/SSH_KEY (or legacy REDSTRIKE_WS01_*) or pass --host/--user/--key",
            file=sys.stderr,
        )
        return 1

    with tempfile.TemporaryDirectory(prefix="redstrike-stage-") as tmp:
        local = Path(tmp) / stage_name
        local.write_bytes(payload)
        try:
            _ensure_remote_dir(settings, directory)
            remote_path = _push(settings, local, directory, stage_name)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    result = {
        "tool": spec.name,
        "staged_to": remote_path,
        "stage_name": stage_name,
        "bytes": len(payload),
        "sha256": digest,
        "pinned": bool(spec.sha256),
        "verified": artifact_verified,
    }
    if artifact_sha:
        result["artifact_sha256"] = artifact_sha
    if note:
        result["note"] = note
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"staged {stage_name} -> {remote_path} ({len(payload)} bytes, sha256 {digest})"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redstrike stage",
        description="Provision Windows beachhead tooling (pinned downloads or local files) "
        "and show where run-time discovery expects it.",
    )
    parser.add_argument("--plan", action="store_true", help="Show the Windows tooling plan (default action)")
    parser.add_argument("--tool", default=None, help="Tool name from the manifest (rubeus, mimikatz, …)")
    parser.add_argument("--download", action="store_true", help="Fetch the pinned upstream artifact and verify sha256")
    parser.add_argument("--file", default=None, help="Stage this local file instead")
    parser.add_argument("--name", default=None, help="Override the remote filename")
    parser.add_argument("--dir", default=None, help="Remote tools directory (default REDSTRIKE_WINDOWS_TOOLS_DIR)")
    parser.add_argument("--host", default=None, help="Beachhead host (default REDSTRIKE_WINDOWS_HOST)")
    parser.add_argument("--user", default=None, help="SSH user (default REDSTRIKE_WINDOWS_USER)")
    parser.add_argument("--key", default=None, help="SSH private key (default REDSTRIKE_WINDOWS_SSH_KEY)")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.tool:
            return _stage_one(args)
        return _plan(args)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
