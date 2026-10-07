"""Unified `redstrike` CLI (check + campaign passthrough)."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redstrike", description="RedStrike — AD/ADCS engine")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Verify install, scope file, and operator tools")
    check.add_argument("--scope", default="scope.yaml")
    check.add_argument("--execute-ready", action="store_true")
    check.add_argument("--version-gated", action="store_true", help="Fail if installed tools do not satisfy minimum version manifest")
    check.add_argument("--ungated", action="store_true")
    check.add_argument("--json", action="store_true")
    check.add_argument("--graph", default=None, help="Report tool readiness for a campaign graph's intents")

    sub.add_parser("campaign", help="Campaign orchestrator (same as redstrike-campaign)")
    sub.add_parser("graph", help="DAG Graph orchestrator (run custom or generic graphs)")
    sub.add_parser("c2", help="C2Stack Flight Control client (fleet, builds, staging, tasking)")
    sub.add_parser("report", help="Engagement report (markdown/JSON from state + journal + ledger)")
    sub.add_parser("stage", help="Provision Windows beachhead tooling (pinned downloads / local files)")
    sub.add_parser("install", help="Provision Linux tooling from manifest recipes (local/container/ssh)")
    sub.add_parser("replay", help="Re-play a recorded graph against the verification engine (10.1 eval harness)")
    sub.add_parser("api", help="HTTP API (same as redstrike-api)")
    sub.add_parser("console", help="Read-only campaign dashboard")
    sub.add_parser("ui", help="Open the cockpit (starts the API if needed)")

    args, rest = parser.parse_known_args(argv)
    if args.command == "check":
        from redstrike.cli.check import run_check

        return run_check(
            scope=args.scope,
            execute_ready=args.execute_ready,
            version_gated=args.version_gated,
            as_json=args.json,
            ungated=bool(getattr(args, "ungated", False)),
            graph=getattr(args, "graph", None),
        )
    if args.command in ("campaign", "graph"):
        from redstrike.cli.campaign import main as campaign_main

        return campaign_main(rest)
    if args.command == "c2":
        from redstrike.cli.c2 import main as c2_main

        return c2_main(rest)
    if args.command == "report":
        from redstrike.cli.report import main as report_main

        return report_main(rest)
    if args.command == "stage":
        from redstrike.cli.stage import main as stage_main

        return stage_main(rest)
    if args.command == "install":
        from redstrike.cli.install import main as install_main

        return install_main(rest)
    if args.command == "replay":
        from redstrike.cli.replay import main as replay_main

        return replay_main(rest)
    if args.command == "ui":
        from redstrike.cli.ui import main as ui_main

        return ui_main(rest)
    if args.command == "api":
        from redstrike.api.server import main as api_main

        api_main(rest)
        return 0
    if args.command == "console":
        from redstrike.cli.console import main as console_main

        return console_main(rest)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
