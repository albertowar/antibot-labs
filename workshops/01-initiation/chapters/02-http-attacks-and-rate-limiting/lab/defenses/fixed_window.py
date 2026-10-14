"""
fixed_window (Round 2): N requests per address per window, windows aligned to the clock.

    policy.FIXED_WINDOW = (limit, window)    20 requests per 10 s

The oldest limiter there is: one counter per (address, window), INCR on every request,
EXPIRE so it cleans itself up. INCR is atomic in Redis, so two app servers sharing one Redis
cannot both read 19 and both write 20. The window index is now // window, so every client's
windows open and close at the same instants.

What it catches: volume from one address. A flood gets `limit` per window, then 429s.
What it misses: the boundary. The counter forgets everything when the window rolls over, so
a client can send `limit` requests in the last instant of one window and `limit` more in the
first instant of the next: twice the limit in well under a second. The 429 even says when
the next window opens (Retry-After), so the attacker need not guess where the edge is.
Who it hurts: people who share an address (carrier NAT, offices), like any per-address limit.
Cost: one key per active address per window, two Redis commands a request. Cheapest there is.

Keys on client_ip(ctx).
"""

import math
import time

from . import policy
from .client_ip import client_ip
from .pipeline import Check, Signal, Verdict


def hit(redis, key, limit, window, now=None):
    """Count one request for `key` in the current clock-aligned window.

    Returns (allowed, retry_after_seconds). Split out so tools/limiter_lab.py can drive it
    with an injected clock and compare it against the other algorithms.
    """
    now = time.time() if now is None else now
    slot = int(now // window)
    k = f"lab:rl:fw:{key}:{slot}"
    p = redis.pipeline()
    p.incr(k)
    p.expire(k, window + 1)
    n = p.execute()[0]
    if n <= limit:
        return True, 0
    return False, max(1, math.ceil((slot + 1) * window - now))


def _check(ctx):
    ip = client_ip(ctx)
    limit, window = policy.FIXED_WINDOW
    # TODO (Round 2): spend this request against hit(ctx.redis, ip, limit, window) above.
    # When it refuses, return Verdict("rate_limit", retry_after=<what hit computed>,
    # signals=(Signal("rate_limit", "fixed_window", 0, ip),)) — the Retry-After header is
    # how a 429 stays polite. Watch hit() on its own first: python tools/limiter_lab.py.
    return None


CHECK = Check("fixed_window", _check)
