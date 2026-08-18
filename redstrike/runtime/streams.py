"""Thin stream runners for Campaign E (network defense) and F (supply-chain).

These are standalone exercise streams — no ws01 routing, no AD credential ledger
required. Operators use `redstrike-campaign stream E|F` or `--branch E|F` with
phases 9 / 10.
"""

from __future__ import annotations

from typing import Any

from redstrike.runtime.graph import STREAM_SPECS


def resolve_stream(stream: str) -> dict[str, str]:
    key = stream.strip().upper()
    if key not in STREAM_SPECS:
        known = ", ".join(sorted(STREAM_SPECS))
        raise ValueError(f"unknown stream '{stream}'; known={known}")
    return dict(STREAM_SPECS[key])


def stream_help() -> list[dict[str, Any]]:
    return [
        {
            "stream": name,
            "branch": spec["branch"],
            "phase": spec["phase"],
            "default_beachhead": spec["beachhead"],
            "notes": "external60_phase0 — no ws01 routing",
        }
        for name, spec in sorted(STREAM_SPECS.items())
    ]
