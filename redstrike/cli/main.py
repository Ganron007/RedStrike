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

    sub.add_parser("campaign", help="Campaign orchestrator (same as redstrike-campaign)")
    sub.add_parser("graph", help="DAG Graph orchestrator (run custom or generic graphs)")
    sub.add_parser("api", help="HTTP API (same as redstrike-api)")
    sub.add_parser("console", help="Interactive TUI campaign dashboard")

    args, rest = parser.parse_known_args(argv)
    if args.command == "check":
        from redstrike.cli.check import run_check

        return run_check(
            scope=args.scope,
            execute_ready=args.execute_ready,
            version_gated=args.version_gated,
            as_json=args.json,
            ungated=bool(getattr(args, "ungated", False)),
        )
    if args.command in ("campaign", "graph"):
        from redstrike.cli.campaign import main as campaign_main

        return campaign_main(rest)
    if args.command == "api":
        from redstrike.api.server import main as api_main

        api_main(rest)
        return 0
    if args.command == "console":
        from redstrike.cli.console import run_console

        return run_console()
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
