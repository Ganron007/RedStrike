"""`redstrike console` — read-only campaign dashboard (real engagement data).

Renders the live engagement state, the journaled steps, the credential ledger
(masked), and the teardown queue with rich. ``--watch`` refreshes on an
interval; ``--json`` prints the same bundle as JSON. This is a *viewer*: it
never approves gates or executes anything.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from redstrike.reporting.engagement import load_engagement_bundle

console = Console(highlight=False)

_VERIFY_STYLE = {
    "verified": "bold green",
    "unverified": "bold red",
    "dry_run": "cyan",
    "skipped": "yellow",
    "stub": "dim",
    "gate": "bold magenta",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redstrike console",
        description="Read-only dashboard for one engagement (state, steps, ledger, teardown).",
    )
    parser.add_argument("--engage", default="demo", help="Engagement id (default: demo)")
    parser.add_argument("--watch", action="store_true", help="Refresh continuously")
    parser.add_argument("--interval", type=float, default=5.0, help="Refresh seconds with --watch")
    parser.add_argument("--json", action="store_true", help="Print the bundle as JSON and exit")
    parser.add_argument("--ledger-root", dest="ledger_root", default=None)
    parser.add_argument("--steps", type=int, default=15, help="How many recent steps to show")
    return parser


def _render(bundle: dict, steps_shown: int) -> None:
    state = bundle["state"]
    summary = bundle["summary"]

    header = Text.assemble(
        ("REDSTRIKE — CAMPAIGN CONSOLE  ", "bold red"),
        (f"[{bundle['engagement_id']}]  ", "bold white"),
        (f"status={summary['status']}", "green" if summary["status"] != "paused" else "yellow"),
        (f"  verified={summary['verified']}", "green"),
        (f"  unverified={summary['unverified']}", "red" if summary["unverified"] else "dim"),
        (f"  creds={summary['credentials']}", "cyan"),
        (f"  beachhead={state.get('beachhead')}", "blue"),
        (f"  operator={state.get('operator')}", "blue"),
    )
    console.print(Panel(header, style="red"))
    if summary.get("pending_gate"):
        console.print(
            Panel(
                Text(
                    f"HITL gate '{summary['pending_gate']}' awaiting approval — "
                    f"redstrike campaign approve --engage {bundle['engagement_id']} --gate {summary['pending_gate']}",
                    style="bold yellow",
                )
            )
        )

    steps = bundle.get("steps") or []
    table = Table(title=f"Journal steps (last {steps_shown})", expand=True)
    table.add_column("Node", style="cyan", no_wrap=True)
    table.add_column("Phase", justify="right")
    table.add_column("Status")
    table.add_column("Mechanism")
    table.add_column("Finished")
    for step in steps[-steps_shown:]:
        status = step.get("verify_status") or ("dry_run" if step.get("dry_run") else "-")
        if step.get("skipped"):
            status = "skipped"
        if step.get("verified"):
            status = "verified"
        table.add_row(
            str(step.get("node_id") or ""),
            str(step.get("phase") or ""),
            Text(str(status), style=_VERIFY_STYLE.get(str(status), "white")),
            str(step.get("mechanism") or ""),
            str(step.get("finished_at") or ""),
        )
    if not steps:
        table.add_row("(none)", "", "no journaled steps", "", "")
    console.print(Panel(table, title="Execution engine", style="dim"))

    creds = bundle.get("credentials") or []
    creds_table = Table(title="Credential ledger (masked)", expand=True)
    creds_table.add_column("Name", style="yellow")
    creds_table.add_column("Username")
    creds_table.add_column("Domain")
    creds_table.add_column("Source")
    creds_table.add_column("Material")
    for cred in creds:
        material = "password" if cred.get("has_password") else ""
        if cred.get("has_nt_hash"):
            material = f"{material} + hash".strip()
        creds_table.add_row(
            str(cred.get("name") or ""),
            str(cred.get("username") or ""),
            str(cred.get("domain") or ""),
            str(cred.get("source") or ""),
            material or "—",
        )
    if not creds:
        creds_table.add_row("(none)", "", "", "", "")
    console.print(Panel(creds_table, title="Discovered identities", style="dim"))

    teardown = [a for a in (bundle.get("teardown") or []) if not a.get("executed")]
    if teardown:
        lines = "\n".join(f"- {a.get('name')} on {a.get('target')}: {a.get('description')}" for a in teardown)
        console.print(Panel(Text(lines), title="Pending teardown", style="yellow"))

    console.print(
        Text(
            "Read-only view. Commands: `redstrike campaign run|approve|teardown`, `redstrike report`. "
            "Ctrl-C to exit.",
            style="dim",
        )
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.ledger_root) if args.ledger_root else None

    def _load() -> dict:
        bundle = load_engagement_bundle(args.engage, root=root)
        bundle["generated_at"] = datetime.now(timezone.utc).isoformat()
        return bundle

    try:
        bundle = _load()
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(bundle, indent=2, default=str))
        return 0

    if not args.watch:
        _render(bundle, args.steps)
        return 0

    try:
        while True:
            console.clear()
            _render(bundle, args.steps)
            time.sleep(max(1.0, args.interval))
            bundle = _load()
    except KeyboardInterrupt:
        console.print("[dim]console closed[/dim]")
        return 0


if __name__ == "__main__":
    sys.exit(main())
