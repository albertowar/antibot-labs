"""
Redis sliding-window primitives (shared helper, not a student exercise).

A sorted set per key, scored by timestamp: evict everything older than the window, add the current
event, count what remains. O(log n) per call and self-expiring. The login defenses build their
IP, account and cohort counters on top of this.

Every key starts with `lab:` so POST /lab/reset (which flushes `lab:*`) wipes the counters between
rounds. The starter's token bucket (ctx.bucket, defenses/store.py) is the other way to rate limit;
this lab uses windows because the lockout and cohort ratios need to *count*, not just admit.

The sliding-window idea is the classic velocity counter of fraud systems, adapted from the
companion code repo's velocity module.
"""

import time
import uuid


def hit(rds, key, window_s, now=None):
    """Record one event under `key` and return the count within `window_s`."""
    now = time.time() if now is None else now
    pipe = rds.pipeline()
    pipe.zremrangebyscore(key, 0, now - window_s)
    pipe.zadd(key, {f"{now}:{uuid.uuid4().hex}": now})
    pipe.zcard(key)
    pipe.expire(key, window_s + 5)
    return pipe.execute()[2]


def incr_window(rds, key, window_s):
    """Fixed-window counter. Returns the new value; the window starts at the first increment.

    Cheaper than a sorted set when all you need is "how many in this window", e.g. a
    consecutive-failure tally that resets on success.
    """
    val = rds.incr(key)
    if val == 1:
        rds.expire(key, window_s)
    return val
