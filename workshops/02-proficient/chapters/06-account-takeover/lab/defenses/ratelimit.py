"""Redis sliding-window primitives (shared helper, not a student exercise).

A sorted set per key, scored by timestamp: evict everything older than the window,
add the current event, count what remains. O(log n) per call and self-expiring.
The defense modules build their IP / account / cohort counters on top of this.

Adapted from the companion repo's ``velocity.py`` (Chapter 21).
"""

from __future__ import annotations

import time
import uuid


def hit(rds, key: str, window_s: int, now: float | None = None) -> int:
    """Record one event under ``key`` and return the count within ``window_s``."""
    now = time.time() if now is None else now
    pipe = rds.pipeline()
    pipe.zremrangebyscore(key, 0, now - window_s)
    pipe.zadd(key, {f"{now}:{uuid.uuid4().hex}": now})
    pipe.zcard(key)
    pipe.expire(key, window_s + 5)
    return pipe.execute()[2]


def count(rds, key: str, window_s: int, now: float | None = None) -> int:
    """Count events under ``key`` within the window without recording a new one."""
    now = time.time() if now is None else now
    rds.zremrangebyscore(key, 0, now - window_s)
    return rds.zcard(key)


def incr_window(rds, key: str, window_s: int, now: float | None = None) -> int:
    """Monotonic per-window counter (fixed window). Returns the new value.

    Cheaper than a sorted set when all you need is "how many in this window",
    e.g. consecutive-failure tallies that reset on success.
    """
    val = rds.incr(key)
    if val == 1:
        rds.expire(key, window_s)
    return val
