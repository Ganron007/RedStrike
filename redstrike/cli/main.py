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
    check.add_argument("--json", action="store_true")

    sub.add_parser("campaign", help="Campaign orchestrator (same as redstrike-campaign)")
    sub.add_parser("api", help="HTTP API (same as redstrike-api)")

    args, rest = parser.parse_known_args(argv)
    if args.command == "check":
        from redstrike.cli.check import run_check

        return run_check(scope=args.scope, execute_ready=args.execute_ready, as_json=args.json)
    if args.command == "campaign":
        from redstrike.cli.campaign import main as campaign_main

        return campaign_main(rest)
    if args.command == "api":
        from redstrike.api.server import main as api_main

        api_main()
        return 0
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
