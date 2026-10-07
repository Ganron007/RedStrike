"""`redstrike replay` — deterministic graph re-runs from recorded outputs (10.1).

Record a live run first:  redstrike graph run ... --record-replay
Then replay it:           redstrike replay --engage E --graph G [--phase 1-3]

Replay feeds the recorded CommandResults back through the normal pipeline
(ordering, depends_on/when, verification, resume), scoring pass/fail per node
against success markers. If a node's argv changed since recording, the step
fails with `replay drift` unless --allow-drift downgrades it to skipped.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from redstrike.runtime.beachhead import Beachhead
from redstrike.runtime.orchestrator import CampaignOrchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redstrike replay",
        description="Re-play a recorded graph against the verification engine "
        "(deterministic pass/fail scoring, no live execution).",
    )
    parser.add_argument("--engage", required=True, help="Engagement holding the recordings")
    parser.add_argument("--graph", required=True, help="Graph YAML (must match the recorded run)")
    parser.add_argument("--phase", default="1-99", help="Phase filter (default: everything recorded)")
    parser.add_argument("--beachhead", default=None, choices=["windows", "linux", "session"])
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--allow-drift",
        action="store_true",
        help="Downgrade argv drift to skipped instead of failed",
    )
    parser.add_argument("--ledger-root", dest="ledger_root", default=None)
    parser.add_argument("--automation-root", dest="automation_root", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ledger_root = Path(args.ledger_root) if args.ledger_root else None
    orch = CampaignOrchestrator(
        engagement_id=args.engage,
        beachhead=Beachhead(args.beachhead or "linux"),
        automation_root=Path(args.automation_root) if args.automation_root else Path("."),
        graph_path=args.graph,
        ledger_root=ledger_root,
        replay_mode=True,
    )

    replay_dir = orch.store.dir / "replay"
    if not replay_dir.is_dir() or not any(replay_dir.glob("*.json")):
        print(
            f"no recordings for engagement '{args.engage}' at {replay_dir} — "
            "record a live run first with: redstrike graph run ... --record-replay",
            file=sys.stderr,
        )
        return 2

    results = orch.run(
        args.phase,
        dry_run=False,
        stop_on_hitl=False,
        allow_drift=args.allow_drift,
    )
    summary = orch.summary(results)
    drift = [
        r.plan.node_id
        for r in results
        if r.skipped and r.skip_reason and "replay drift" in r.skip_reason
    ]
    payload: dict[str, Any] = {
        "engagement_id": args.engage,
        "graph": str(orch.graph_path),
        "graph_name": orch.graph.name,
        "score": {
            "steps": len(results),
            "verified": summary["verified_count"],
            "unverified": summary["unverified_count"],
            "drift": len(drift),
        },
        "steps": [r.to_dict() for r in results],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"Replay [{orch.graph.name}] — verified {summary['verified_count']}, "
              f"unverified {summary['unverified_count']}, drift {len(drift)}")
        for r in results:
            mark = "ok" if r.verified else ("skip" if r.skipped else "FAIL")
            reason = r.verify_reason or r.skip_reason or ""
            print(f"  [{mark:5s}] {r.plan.node_id}: {reason[:90]}")

    if drift and not args.allow_drift:
        print("hint: argv changed since recording — pass --allow-drift to downgrade drift to skipped")
    # Score: pass only when every executed step verified and nothing drifted.
    return 0 if summary["unverified_count"] == 0 and not drift else 1


if __name__ == "__main__":
    sys.exit(main())
