"""UTC activity journal for later log correlation (WinSec / Sysmon / Zeek / Suricata).

One JSON object per line (JSONL) plus a parallel one-line .log.
No passwords, hashes, or raw command output — argv is redacted.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redstrike.core.runner import redact_argv


def utc_now_ms() -> str:
    """Millisecond UTC timestamp: 2026-08-22T10:15:03.123Z"""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(now.microsecond / 1000):03d}Z"


def resolve_activity_log(engagement_id: str, *, ledger_dir: Path | None = None) -> Path | None:
    env = os.environ.get("REDSTRIKE_ACTIVITY_LOG", "").strip()
    if env:
        return Path(env)
    if ledger_dir is not None:
        return Path(ledger_dir) / f"activity-{engagement_id}.jsonl"
    return None


class ActivityJournal:
    """Append-only JSONL + grep-friendly .log next to it."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.text_path = path.with_suffix(".log") if path else None

    def emit(self, event: str, **fields: Any) -> dict[str, Any]:
        record: dict[str, Any] = {"ts": utc_now_ms(), "event": event}
        for key, value in fields.items():
            if value is None:
                continue
            if key == "argv" and isinstance(value, list):
                record[key] = redact_argv(value)
            else:
                record[key] = value
        if self.path is None:
            return record
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, ensure_ascii=True, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if self.text_path is not None:
            node = str(record.get("node_id") or "-")
            title = str(record.get("title") or "")
            extra = str(
                record.get("verify_status")
                or record.get("skip_reason")
                or record.get("phase_spec")
                or ""
            )
            text = f"{record['ts']} {event:18} {node:14} {title} {extra}".rstrip()
            with self.text_path.open("a", encoding="utf-8") as handle:
                handle.write(text + "\n")
        return record
