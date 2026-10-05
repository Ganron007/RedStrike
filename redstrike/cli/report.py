"""`redstrike report` — render an engagement deliverable from live state."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from redstrike.reporting.engagement import (
    load_engagement_bundle,
    render_engagement_json,
    render_engagement_markdown,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redstrike report",
        description="Generate a markdown/JSON report for an engagement from state, journal, ledger, and teardown.",
    )
    parser.add_argument("--engage", required=True, help="Engagement id")
    parser.add_argument("--format", choices=["md", "json"], default="md")
    parser.add_argument("--out", default=None, help="Write to this path (default: stdout)")
    parser.add_argument(
        "--include-secrets",
        action="store_true",
        help="Include raw passwords/hashes (default masks them)",
    )
    parser.add_argument("--ledger-root", dest="ledger_root", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        bundle = load_engagement_bundle(
            args.engage,
            root=Path(args.ledger_root) if args.ledger_root else None,
            include_secrets=args.include_secrets,
        )
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    bundle["generated_at"] = datetime.now(timezone.utc).isoformat()

    if args.format == "json":
        text = json.dumps(render_engagement_json(bundle), indent=2, default=str) + "\n"
    else:
        text = render_engagement_markdown(bundle) + "\n"

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"report written: {args.out} ({len(text)} bytes)")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
