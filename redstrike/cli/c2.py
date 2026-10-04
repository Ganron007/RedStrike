"""`redstrike c2` — drive C2Stack's Flight Control portal from the CLI.

Surfaces the full stack: fleet view, capability probe, per-framework tasking
catalogues, server-side payload builds (sliver / havoc / adaptix / mythic),
Mythic file staging, and redirector verification.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from redstrike.c2.stack import C2StackClient

_MYTHIC_POLL_SECONDS = 15
_MYTHIC_MAX_WAIT = 600


def _client(args: argparse.Namespace) -> C2StackClient:
    return C2StackClient(endpoint=getattr(args, "endpoint", None))


def _emit(data: dict[str, Any], as_json: bool, *, drop: tuple[str, ...] = ()) -> None:
    if as_json:
        printable = {k: v for k, v in data.items() if k not in drop}
        print(json.dumps(printable, indent=2, default=str))
        return
    if data.get("ok") is False:
        print(f"error: {data.get('error')}")
        return
    for key, value in data.items():
        if key in ("ok",) or key in drop:
            continue
        if isinstance(value, (dict, list)):
            print(f"{key}: {json.dumps(value, indent=2, default=str)}")
        else:
            print(f"{key}: {value}")


def _ok(data: dict[str, Any]) -> int:
    return 0 if isinstance(data, dict) and data.get("ok", True) is not False else 1


def _write_payload(data: dict[str, Any], out: str | None, default_name: str) -> dict[str, Any]:
    """Persist a build response's raw bytes to disk."""
    payload = data.get("payload")
    if not isinstance(payload, (bytes, bytearray)):
        return data
    dest = Path(out or str(data.get("filename") or default_name))
    dest.write_bytes(payload)
    data = dict(data)
    data.pop("payload", None)
    data["path"] = str(dest)
    data["size"] = len(payload)
    return data


# ----------------------------------------------------------------- commands
def _cmd_status(args: argparse.Namespace) -> int:
    client = _client(args)
    data = client.status()
    if args.json:
        _emit(data, True)
        return _ok(data)
    services = data.get("services") or {}
    print(f"portal: {client.endpoint} (docker_available={data.get('docker_available')})")
    for name, info in services.items():
        state = info.get("state") if isinstance(info, dict) else "?"
        live = info.get("port_live") if isinstance(info, dict) else None
        prefix = info.get("uri_prefix") if isinstance(info, dict) else None
        print(f"  {name:10s} {state or '?':10s} port_live={live} prefix={prefix or '-'}")
    return 0 if services else 1


def _cmd_sessions(args: argparse.Namespace) -> int:
    client = _client(args)
    data = client.sessions(backend=args.backend)
    if args.json:
        _emit(data, True)
        return _ok(data)
    sessions = data.get("sessions") or []
    for backend, info in (data.get("backends") or {}).items():
        if isinstance(info, dict) and info.get("ok") is False:
            print(f"  [{backend}] unreachable: {str(info.get('error'))[:120]}")
    for s in sessions:
        print(
            f"  {s.get('backend', '?'):9s} {s.get('id', '')!s:36s} "
            f"{s.get('hostname', '?')!s:14s} {s.get('username', '?')!s:18s} "
            f"alive={s.get('is_alive')} {str(s.get('os', ''))[:28]}"
        )
    print(f"{len(sessions)} session(s)")
    return 0 if not isinstance(data, dict) or data.get("ok", True) is not False else 1


def _cmd_capabilities(args: argparse.Namespace) -> int:
    client = _client(args)
    data = client.capabilities()
    _emit(data, args.json)
    return _ok(data)


def _cmd_catalogues(args: argparse.Namespace) -> int:
    client = _client(args)
    data = client.catalogues(backend=args.backend)
    if args.json:
        _emit(data, True)
        return _ok(data)
    commands = data.get("commands") if args.backend else data
    if isinstance(commands, dict):
        for name, spec in commands.items():
            if isinstance(spec, dict):
                help_text = spec.get("help") or spec.get("example") or ""
                print(f"  {name:18s} {help_text}")
            else:
                print(f"  {name}")
    return _ok(data)


def _cmd_probe(args: argparse.Namespace) -> int:
    client = _client(args)
    headers = json.loads(args.headers) if args.headers else {}
    data = client.probe_redirector(url_path=args.path, headers=headers, method=args.method)
    _emit(data, args.json, drop=("preview",))
    if not args.json:
        print(f"verdict: {data.get('verdict')} — {data.get('explanation')}")
    return _ok(data)


def _cmd_stage(args: argparse.Namespace) -> int:
    client = _client(args)
    data = client.stage_file(args.file)
    _emit(data, args.json)
    if not args.json and data.get("ok"):
        print(f"staged: agent_file_id={data.get('agent_file_id')}")
    return _ok(data)


def _cmd_task(args: argparse.Namespace) -> int:
    client = _client(args)
    data = client.task(
        backend=args.backend,
        session_id=args.session,
        command=args.command,
        wait=args.wait,
        callback_id=args.callback_id,
    )
    if args.json:
        _emit(data, True)
        return _ok(data)
    result = data.get("result") if isinstance(data, dict) else None
    if isinstance(result, dict):
        output = result.get("output") or result.get("a_text") or ""
        print(output or json.dumps(result, indent=2, default=str))
    elif data.get("ok") is False:
        print(f"error: {data.get('error')}")
    return _ok(data)


def _build_sliver(client: C2StackClient, args: argparse.Namespace) -> dict[str, Any]:
    data = client.build_sliver(
        kind=args.kind, c2_url=args.c2_url, target_os=args.target_os, arch=args.arch
    )
    if data.get("ok") and args.retrieve:
        container_path = str(data.get("container_path") or "")
        if container_path:
            dest = Path(args.out or f"sliver-{args.kind}-{args.arch}.exe")
            fetched = client.retrieve_container_file(container_path, dest)
            data = dict(data)
            data["retrieved"] = fetched
    return data


def _build_havoc(client: C2StackClient, args: argparse.Namespace) -> dict[str, Any]:
    data = client.build_havoc(
        arch=args.arch, format=args.havoc_format, listener=args.listener,
        sleep=args.sleep, jitter=args.jitter,
    )
    return _write_payload(data, args.out, f"demon-{args.arch}.exe")


def _build_adaptix(client: C2StackClient, args: argparse.Namespace) -> dict[str, Any]:
    data = client.build_adaptix(
        agent=args.agent, listener=args.listener, arch=args.arch,
        format=args.adaptix_format, sleep=args.sleep,
        ensure_listener=args.ensure_listener,
    )
    return _write_payload(data, args.out, f"adaptix-{args.agent}-{args.arch}.bin")


def _build_mythic(client: C2StackClient, args: argparse.Namespace) -> dict[str, Any]:
    import time

    overrides: dict[str, Any] = {"output_type": args.output_type, "filename": args.filename}
    if args.keying_method:
        overrides.update(
            enable_keying=True,
            keying_method=args.keying_method,
            keying_value=args.keying_value or "",
        )
    data = client.build_mythic(**overrides)
    if data.get("ok") is False or args.no_wait:
        return data
    payload_uuid = str(data.get("uuid") or "")
    deadline = time.monotonic() + args.max_wait
    while payload_uuid and time.monotonic() < deadline:
        status = client.mythic_build_status(payload_uuid)
        phase = str(status.get("phase") or "")
        print(f"  build {payload_uuid[:8]} phase={phase} {str(status.get('message') or '')[:100]}")
        if phase == "success":
            download = client.mythic_download(payload_uuid, dest=args.out)
            download["uuid"] = payload_uuid
            return download
        if phase == "error":
            return {"ok": False, "error": status.get("stderr") or "mythic build failed"}
        time.sleep(args.poll_seconds)
    return {"ok": False, "error": f"mythic build {payload_uuid} did not finish within {args.max_wait}s"}


def _cmd_build(args: argparse.Namespace) -> int:
    client = _client(args)
    builders = {
        "sliver": _build_sliver,
        "havoc": _build_havoc,
        "adaptix": _build_adaptix,
        "mythic": _build_mythic,
    }
    data = builders[args.backend](client, args)
    if args.json:
        _emit(data, True, drop=("payload",))
        return _ok(data)
    if data.get("ok") is False:
        print(f"error: {data.get('error')}")
        return 1
    kind = data.get("path") or data.get("container_path") or data.get("uuid") or ""
    print(f"built via {args.backend}: {kind}")
    if data.get("retrieve"):
        print(f"retrieve: {data['retrieve']}")
    if isinstance(data.get("retrieved"), dict) and data["retrieved"].get("path"):
        print(f"saved: {data['retrieved']['path']} ({data['retrieved'].get('size')} bytes)")
    elif data.get("path"):
        print(f"saved: {data['path']} ({data.get('size')} bytes)")
    return 0


# -------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redstrike c2", description="C2Stack Flight Control client")
    parser.add_argument("--endpoint", default=None, help="Portal base URL (default C2STACK_PORTAL_URL or http://127.0.0.1:8000)")
    sub = parser.add_subparsers(dest="c2_command", required=True)

    status = sub.add_parser("status", help="Stack service health (containers, ports, prefixes)")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=_cmd_status)

    sessions = sub.add_parser("sessions", help="Unified live fleet (sessions + beacons, all frameworks)")
    sessions.add_argument("--backend", default=None, help="Filter to one framework")
    sessions.add_argument("--json", action="store_true")
    sessions.set_defaults(func=_cmd_sessions)

    caps = sub.add_parser("capabilities", help="Live capability probe per framework")
    caps.add_argument("--json", action="store_true")
    caps.set_defaults(func=_cmd_capabilities)

    cats = sub.add_parser("catalogues", help="Tasking vocabulary (per framework)")
    cats.add_argument("--backend", default=None)
    cats.add_argument("--json", action="store_true")
    cats.set_defaults(func=_cmd_catalogues)

    probe = sub.add_parser("probe", help="Probe the redirector (decoy vs backend routing)")
    probe.add_argument("--path", default="/", help="Request URI path (e.g. /gateway/v1/telemetry)")
    probe.add_argument("--headers", default=None, help='JSON headers, e.g. \'{"X-Request-ID": "cadre-c2"}\'')
    probe.add_argument("--method", default="GET")
    probe.add_argument("--json", action="store_true")
    probe.set_defaults(func=_cmd_probe)

    stage = sub.add_parser("stage", help="Stage a file in Mythic (COFF/assembly/PE flows)")
    stage.add_argument("file", help="Local file path")
    stage.add_argument("--json", action="store_true")
    stage.set_defaults(func=_cmd_stage)

    task = sub.add_parser("task", help="Task ANY framework session through the portal")
    task.add_argument("--backend", required=True, help="meridian | mythic | havoc | adaptix | sliver")
    task.add_argument("--session", required=True, help="Session/beacon id")
    task.add_argument("--command", required=True)
    task.add_argument("--wait", type=int, default=25)
    task.add_argument("--callback-id", dest="callback_id", type=int, default=None, help="Mythic callback id when it differs from the session id")
    task.add_argument("--json", action="store_true")
    task.set_defaults(func=_cmd_task)

    build = sub.add_parser("build", help="Server-side payload builds (sliver/havoc/adaptix/mythic)")
    build.add_argument("--backend", required=True, choices=["sliver", "havoc", "adaptix", "mythic"])
    build.add_argument("--out", default=None, help="Write the payload to this path")
    build.add_argument("--json", action="store_true")
    # sliver
    build.add_argument("--kind", default="session", choices=["session", "beacon"])
    build.add_argument("--c2-url", dest="c2_url", default=None, help="Implant callback URL (redirector prefix)")
    build.add_argument("--target-os", dest="target_os", default="windows")
    build.add_argument("--arch", default="x64", help="sliver: amd64|386 — havoc/adaptix: x64|x86")
    build.add_argument("--retrieve", action="store_true", help="sliver: docker cp the built implant to --out")
    # havoc
    build.add_argument("--havoc-format", dest="havoc_format", default="Windows Exe")
    build.add_argument("--listener", default=None, help="havoc listener name / adaptix listener instance")
    build.add_argument("--sleep", default=None, help="havoc: seconds; adaptix: e.g. 30s")
    build.add_argument("--jitter", type=int, default=15, help="havoc jitter (adaptix is forced to 0)")
    # adaptix
    build.add_argument("--agent", default="beacon")
    build.add_argument("--adaptix-format", dest="adaptix_format", default="Exe")
    build.add_argument("--ensure-listener", dest="ensure_listener", action="store_true")
    # mythic
    build.add_argument("--output-type", dest="output_type", default="WinExe", choices=["WinExe", "Shellcode", "Service", "Source"])
    build.add_argument("--filename", default="apollo-portal.exe")
    build.add_argument("--keying-method", dest="keying_method", default=None, choices=["Hostname", "Domain", "Registry"])
    build.add_argument("--keying-value", dest="keying_value", default=None)
    build.add_argument("--no-wait", dest="no_wait", action="store_true", help="mythic: queue and return the uuid")
    build.add_argument("--poll-seconds", dest="poll_seconds", type=int, default=_MYTHIC_POLL_SECONDS)
    build.add_argument("--max-wait", dest="max_wait", type=int, default=_MYTHIC_MAX_WAIT)
    build.set_defaults(func=_cmd_build)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # backend-specific defaults resolved here to keep the shared flags free-form
    if getattr(args, "func", None) is _cmd_build:
        if args.backend == "sliver":
            args.arch = "amd64" if args.arch in ("x64", "amd64") else args.arch
        if args.backend == "havoc":
            args.arch = "x64" if args.arch in ("amd64", "x64") else args.arch
            args.sleep = int(args.sleep) if args.sleep is not None else 5
            args.listener = args.listener or "c2stack - http"
        if args.backend == "adaptix":
            args.arch = "x64" if args.arch in ("amd64", "x64") else args.arch
            args.sleep = str(args.sleep) if args.sleep is not None else "30s"
            args.listener = args.listener or "cadre_http"
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
