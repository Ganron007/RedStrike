"""Reference agent loop: an LLM (or the offline stub) driving RedStrike over its API.

Phase 10.2 example. ~150 lines, no SDK dependencies — everything goes through
the same gated REST endpoints an operator uses, so scope policy, HITL gates,
and the audit trail apply identically. The agent NEVER bypasses a gate: when a
run pauses for approval, the loop stops and reports.

Usage:
  python redstrike_agent.py --api http://127.0.0.1:8890 --engage demo --offline
  python redstrike_agent.py --api ... --provider anthropic  # ANTHROPIC_API_KEY env

The offline stub is the deterministic eval target: it picks recommendations in
rank order, so `redstrike replay` fixtures + this agent give a repeatable
regression test for "does the agent reach the same verified end-state".
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import requests

MAX_ITERATIONS = 12


class OfflineStub:
    """Deterministic stand-in for an LLM: always the top recommendation."""

    name = "offline-stub"

    def next_action(self, _state: dict, recommendations: list[dict]) -> dict:
        return recommendations[0] if recommendations else {}


class AnthropicClient:
    """Minimal Anthropic messages client (tool-use style, one decision per turn)."""

    name = "anthropic"

    def __init__(self) -> None:
        self.key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.key:
            raise SystemExit("ANTHROPIC_API_KEY not set")

    def next_action(self, state: dict, recommendations: list[dict]) -> dict:
        prompt = (
            "You are steering an authorized AD assessment. Engagement state:\n"
            f"{json.dumps(state, indent=1)[:2000]}\n\nCandidate next actions:\n"
            f"{json.dumps(recommendations[:3], indent=1)}\n\n"
            "Return ONLY JSON: {\"node_id\": \"...\"} for the action to take next."
        )
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": self.key, "anthropic-version": "2023-06-01"},
            json={"model": "claude-3-haiku-20240307", "max_tokens": 200,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=60,
        )
        resp.raise_for_status()
        text = resp.json()["content"][0]["text"]
        start, end = text.find("{"), text.rfind("}") + 1
        return json.loads(text[start:end]) if start >= 0 else {}


def run(api: str, agent: Any, engage: str, execute: bool) -> int:
    headers = {"Content-Type": "application/json"}

    def post(path: str, payload: dict) -> dict:
        r = requests.post(api + path, json=payload, headers=headers, timeout=300)
        r.raise_for_status()
        return r.json()

    for iteration in range(MAX_ITERATIONS):
        rec = post("/campaign/recommend", {"engagement_id": engage})
        actionable = [r for r in rec.get("recommendations", []) if r.get("actionable")]
        if not actionable:
            print(f"[agent] nothing actionable remains (iteration {iteration})")
            return 0
        pick = agent.next_action(rec, actionable)
        node_id = pick.get("node_id", "")
        print(f"[agent] iteration {iteration}: -> {node_id}")

        # Dry-run first (same gated path an operator uses), then live.
        result = post("/campaign/run_phase", {
            "engagement_id": engage, "phase": str(rec["recommendations"][0]["phase"]),
            "dry_run": True, "nodes": node_id,
        })
        steps = result.get("steps", [])
        gate = next((s for s in steps if s.get("awaiting_approval")), None)
        if gate:
            print(f"[agent] STOP: {node_id} is HITL-gated ({gate.get('hitl_gate')}) — "
                  "human approval required; the agent never bypasses gates.")
            return 3
        if execute:
            result = post("/campaign/run_phase", {
                "engagement_id": engage, "phase": str(rec["recommendations"][0]["phase"]),
                "dry_run": False, "nodes": node_id, "resume": True,
            })
            for s in result.get("steps", []):
                print(f"[agent]   {s['node_id']}: verified={s['verified']} rc={s['return_code']}")

    print("[agent] iteration budget exhausted")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(prog="redstrike_agent")
    ap.add_argument("--api", default="http://127.0.0.1:8890")
    ap.add_argument("--engage", default="demo")
    ap.add_argument("--provider", choices=["offline", "anthropic"], default="offline")
    ap.add_argument("--offline", action="store_true",
                    help="Shorthand for --provider offline (deterministic eval stub)")
    ap.add_argument("--execute", action="store_true", help="Live execution (default: dry-run only)")
    args = ap.parse_args()

    provider = "offline" if args.offline else args.provider
    agent = OfflineStub() if provider == "offline" else AnthropicClient()
    return run(args.api.rstrip("/"), agent, args.engage, execute=args.execute)


if __name__ == "__main__":
    sys.exit(main())
