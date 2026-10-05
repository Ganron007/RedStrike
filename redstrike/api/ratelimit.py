"""Cross-process sliding-window rate limiting (SQLite-backed).

The in-memory limiter in `server.py` is per-process: with `uvicorn --workers N`
(or restarts) each worker gets its own budget, so the effective limit is
N × the configured value. This backend keeps the window in SQLite (WAL +
BEGIN IMMEDIATE) so every worker/process shares one budget.

Failure policy: a broken limiter store must never fail a request — errors are
swallowed (fail-open on the *limiter*, never on scope/HITL).
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from redstrike.core.errors import RateLimitExceededError

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS hits (key TEXT NOT NULL, ts REAL NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_hits_key_ts ON hits (key, ts)",
)


class SqliteRateWindow:
    """Shared sliding window; same call contract as the in-memory limiter."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            for statement in _SCHEMA:
                conn.execute(statement)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def check(self, key: str, max_requests: int, window_seconds: float) -> None:
        if max_requests <= 0 or window_seconds <= 0:
            return
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM hits WHERE ts <= ?", (now - window_seconds,))
            row = conn.execute(
                "SELECT COUNT(*), MIN(ts) FROM hits WHERE key = ?", (key,)
            ).fetchone()
            count = int(row[0] or 0)
            oldest = row[1]
            if count >= max_requests:
                retry_after = max(0.0, window_seconds - (now - (oldest or now)))
                conn.execute("ROLLBACK")
                raise RateLimitExceededError(
                    f"Rate limit exceeded for '{key}': {max_requests} requests per "
                    f"{window_seconds:g}s. Retry after {retry_after:.1f}s"
                )
            conn.execute("INSERT INTO hits (key, ts) VALUES (?, ?)", (key, now))
            # Bound growth for keys/windows we no longer touch (keep a full hour).
            conn.execute("DELETE FROM hits WHERE ts <= ?", (now - max(window_seconds, 3600.0),))
            conn.execute("COMMIT")
        except RateLimitExceededError:
            raise
        except sqlite3.Error:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        finally:
            conn.close()
