from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from redstrike.runtime.beachhead import Beachhead, OperatorMode, detect_default_operator
from redstrike.runtime.graph import KNOWN_BRANCHES, STREAM_SPECS
from redstrike.runtime.hitl import KNOWN_GATES, hitl_required
from redstrike.runtime.session import CampaignSession, default_automation_root, default_seed_path
from redstrike.runtime.streams import resolve_stream


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redstrike-campaign",
        description="Campaign & Generic DAG graph orchestrator. Pass --graph to execute custom or generic attack graphs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser, *, beachhead_required: bool = False) -> None:
        p.add_argument("--engage", required=True, help="Engagement id")
        p.add_argument("--graph", default=None, help="Path to custom or generic DAG graph YAML")
        p.add_argument("--automation-root", default=None)
        p.add_argument(
            "--seed",
            default=None,
            help="JSON seed credentials (default: REDSTRIKE_SEED or examples/seed.example.json)",
        )
        p.add_argument("--allow-mbr01-stage", action="store_true")
        p.add_argument("--json", action="store_true")
        p.add_argument(
            "--branch",
            default="spine",
            help=f"Branches: spine (default), A,B,C,D,H,G,sql-ai, or all. Known={sorted(KNOWN_BRANCHES)}",
        )
        p.add_argument(
            "--profile",
            default=None,
            choices=["gated", "autonomous", "standalone", "campaign", "lab-readonly", "lab-ungated"],
            help="Execution profile: gated (HITL approval, default) or autonomous (unrestricted under scope)",
        )
        p.add_argument(
            "--ungated",
            action="store_true",
            help="Lab mode: no HITL, live-capable. Requires --scope with targets and domains.",
        )
        p.add_argument(
            "--scope",
            default=os.environ.get("REDSTRIKE_SCOPE") or None,
            help="Scope YAML (required with --ungated). Default: REDSTRIKE_SCOPE.",
        )
        p.add_argument(
            "--operator",
            choices=[m.value for m in OperatorMode],
            default=None,
            help=(
                "Where the orchestrator runs: provisioning (SSH to Windows beachhead) "
                "or ws01 (native on that host). Default: win32→ws01, else provisioning "
                "(override with REDSTRIKE_OPERATOR)."
            ),
        )
        if beachhead_required:
            p.add_argument(
                "--beachhead",
                choices=[b.value for b in Beachhead],
                required=True,
            )
        else:
            p.add_argument(
                "--beachhead",
                choices=[b.value for b in Beachhead],
                default="windows",
            )

    check = sub.add_parser("check", help="Verify install, scope file, and operator tools")
    check.add_argument("--scope", default="scope.yaml")
    check.add_argument("--execute-ready", action="store_true")
    check.add_argument("--version-gated", action="store_true", help="Fail if installed tools do not satisfy minimum version manifest")
    check.add_argument("--ungated", action="store_true")
    check.add_argument("--json", action="store_true")

    start = sub.add_parser("start", help="Create/refresh engagement + seed ledger")
    add_common(start, beachhead_required=True)

    approve = sub.add_parser("approve", help="Approve a HITL gate")
    add_common(approve)
    approve.add_argument("--gate", required=True, choices=sorted(KNOWN_GATES))
    approve.add_argument("--note", default=None)

    run = sub.add_parser("run", help="Plan or execute campaign phases / branches")
    add_common(run, beachhead_required=True)
    run.add_argument("--phase", default="1-3", help="e.g. 1-3 or 0.5-8 (ignored when --nodes is set)")
    run.add_argument("--execute", action="store_true")
    run.add_argument("--no-stop-on-hitl", action="store_true")
    run.add_argument("--no-preflight", action="store_true")
    run.add_argument(
        "--prefer-script",
        action="store_true",
        help="Use script harness instead of typed intent when both are set",
    )
    run.add_argument(
        "--nodes",
        default=None,
        help="Comma-separated graph node ids (ignores --phase/--branch; still filtered by --beachhead)",
    )

    status = sub.add_parser("status", help="Show engagement state + preflight")
    add_common(status)

    stream = sub.add_parser(
        "stream",
        help=f"Run standalone E/F streams (known={sorted(STREAM_SPECS)}) — no ws01 routing",
    )
    add_common(stream)
    # Streams always egress from provisioning; default beachhead=linux (override add_common).
    for action in stream._actions:
        if getattr(action, "dest", None) == "beachhead":
            action.default = "linux"
            break
    stream.add_argument("name", choices=sorted(STREAM_SPECS), help="Stream E or F")
    stream.add_argument("--execute", action="store_true")
    stream.add_argument("--no-preflight", action="store_true")

    return parser


def _session_from_args(args: argparse.Namespace) -> CampaignSession:
    automation_root = Path(args.automation_root) if args.automation_root else default_automation_root()
    seed = args.seed if getattr(args, "seed", None) else None
    operator = getattr(args, "operator", None) or detect_default_operator()
    return CampaignSession(
        args.engage,
        beachhead=getattr(args, "beachhead", "windows") or "windows",
        operator=operator,
        automation_root=automation_root,
        graph_path=args.graph,
        allow_mbr01_stage=bool(getattr(args, "allow_mbr01_stage", False)),
        seed_path=seed or default_seed_path(),
        branches=getattr(args, "branch", "spine"),
        prefer_script=bool(getattr(args, "prefer_script", False)),
        node_ids=getattr(args, "nodes", None),
        profile=getattr(args, "profile", None),
    )


def _execute_unverified(data: dict) -> bool:
    """True when a live (non-dry-run) step ran and was not verified."""
    for step in data.get("steps", []):
        if step.get("dry_run") or step.get("skipped") or step.get("awaiting_approval"):
            continue
        if not step.get("verified"):
            return True
    return False


def _print(data: dict, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, indent=2))
        return
    if "steps" in data:
        mode = "DRY-RUN" if all(s.get("dry_run", True) for s in data["steps"]) else "EXECUTE"
        print(f"[{mode}] engagement={data['engagement_id']} beachhead={data['beachhead']} operator={data.get('operator')}")
        print(f"graph={data['graph']} branches={data.get('branches')}")
        pf = data.get("preflight") or {}
        if pf:
            print(f"preflight profile={pf.get('profile')} hosts={pf.get('required_hosts')}")
            for w in pf.get("warnings") or []:
                print(f"  warn: {w}")
        state = data.get("state") or {}
        if state.get("pending_gate"):
            print(f"pending_gate={state['pending_gate']} status={state.get('status')}")
        print(
            f"ws01_exec={data.get('ws01_exec_count', 0)} "
            f"local_ws01={data.get('local_ws01_count', 0)} "
            f"linux_direct={data.get('linux_direct_count', 0)} "
            f"mbr01={data.get('mbr01_count', 0)} "
            f"awaiting={data.get('awaiting_approval_count', 0)} "
            f"stubs={data.get('stub_count', 0)} "
            f"verified={data.get('verified_count', 0)} "
            f"unverified={data.get('unverified_count', 0)}"
        )
        for step in data["steps"]:
            if step.get("awaiting_approval"):
                flag = "GATE"
            elif step.get("skipped"):
                flag = "SKIP"
            elif step.get("dry_run"):
                flag = "PLAN"
            elif step.get("verified"):
                flag = "OK"
            else:
                flag = "FAIL"
            gate = f" hitl={step['hitl_gate']}" if step.get("hitl_gate") else ""
            br = step.get("branch") or "spine"
            print(
                f"  [{flag}] P{step['phase']} [{br}] {step['node_id']} "
                f"path={step['path']} mech={step['mechanism']}{gate}"
            )
            if step.get("skip_reason"):
                print(f"         {step['skip_reason']}")
            if flag == "FAIL" and step.get("verify_reason"):
                print(f"         verify={step['verify_reason']}")
        return
    print(json.dumps(data, indent=2))


def _activate_ungated(args: argparse.Namespace) -> int | None:
    requested = bool(getattr(args, "ungated", False)) or os.environ.get(
        "REDSTRIKE_UNGATED", ""
    ).strip().lower() in {"1", "true", "yes"}
    if not requested:
        return None
    os.environ["REDSTRIKE_UNGATED"] = "1"
    scope = getattr(args, "scope", None)
    if not scope:
        print(
            "--ungated requires --scope (or REDSTRIKE_SCOPE) with non-empty "
            "allowed_targets and allowed_domains",
            file=sys.stderr,
        )
        return 2
    from redstrike.core.policy import apply_ungated_overrides, load_scope_policy

    try:
        policy = load_scope_policy(str(scope), profile="lab-ungated")
        apply_ungated_overrides(policy)
        policy.require_scope_ready()
    except (OSError, PermissionError, ValueError) as extra:
        print(str(extra), file=sys.stderr)
        return 2
    return None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        from redstrike.cli.check import run_check

        return run_check(
            scope=args.scope,
            execute_ready=bool(args.execute_ready),
            version_gated=bool(getattr(args, "version_gated", False)),
            as_json=bool(args.json),
            ungated=bool(getattr(args, "ungated", False)),
        )

    ungated_error = _activate_ungated(args)
    if ungated_error is not None:
        return ungated_error

    session = _session_from_args(args)

    if args.command == "start":
        _print(session.start(), as_json=args.json)
        return 0

    if args.command == "approve":
        _print(session.approve(args.gate, note=args.note), as_json=args.json)
        return 0

    if args.command == "status":
        _print(session.status(), as_json=True)
        return 0

    if args.command == "run":
        try:
            data = session.run_phase(
                args.phase,
                dry_run=not args.execute,
                stop_on_hitl=not args.no_stop_on_hitl,
                profile=args.profile,
                include_preflight=not args.no_preflight,
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        _print(data, as_json=args.json)
        if _execute_unverified(data):
            return 1
        if args.execute and any(s.get("awaiting_approval") for s in data.get("steps", [])):
            return 3
        return 0

    if args.command == "stream":
        spec = resolve_stream(args.name)
        # Rebuild session with stream branch + default linux beachhead unless overridden.
        session = CampaignSession(
            args.engage,
            beachhead=getattr(args, "beachhead", None) or spec["beachhead"],
            operator=getattr(args, "operator", None) or detect_default_operator(),
            automation_root=Path(args.automation_root) if args.automation_root else default_automation_root(),
            graph_path=args.graph,
            allow_mbr01_stage=bool(getattr(args, "allow_mbr01_stage", False)),
            seed_path=(args.seed if getattr(args, "seed", None) else None) or default_seed_path(),
            branches=spec["branch"],
            prefer_script=False,
            profile=getattr(args, "profile", None),
        )
        data = session.run_phase(
            spec["phase"],
            dry_run=not args.execute,
            stop_on_hitl=hitl_required(getattr(args, "profile", None)),
            profile=args.profile,
            include_preflight=not args.no_preflight,
        )
        data["stream"] = args.name.upper()
        _print(data, as_json=args.json)
        return 1 if _execute_unverified(data) else 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
