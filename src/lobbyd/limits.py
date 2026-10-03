"""Per-key rate limiting and audit retention (room-o-matic/docs#11)."""

import sqlite3
import threading
import time
from collections import deque
from datetime import UTC, datetime, timedelta


class RateLimiter:
    """Sliding one-minute window per key. In memory: a restart resets it, which is fine
    for a guard against floods rather than an accounting system."""

    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> float | None:
        """None if allowed (and counted); else seconds until the next request may pass."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] >= 60:
                hits.popleft()
            if len(hits) >= self.per_minute:
                return max(0.0, 60 - (now - hits[0]))
            hits.append(now)
            return None


class AuditPruner:
    """Deletes audit rows older than the retention, at most once per interval."""

    def __init__(self, retention_days: int, interval_seconds: float = 3600):
        self.retention = timedelta(days=retention_days)
        self.interval = interval_seconds
        self._last = 0.0
        self._lock = threading.Lock()

    def maybe_prune(self, conn: sqlite3.Connection) -> int:
        with self._lock:
            if time.monotonic() - self._last < self.interval:
                return 0
            self._last = time.monotonic()
        cutoff = (datetime.now(UTC) - self.retention).isoformat(timespec="milliseconds")
        with conn:
            cur = conn.execute(
                "delete from audit where created_at < ?", (cutoff.replace("+00:00", "Z"),)
            )
        return cur.rowcount
