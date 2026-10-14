"""
sliding_window (Round 3, the alternative to the token bucket): a window without the boundary.

    policy.SLIDING_WINDOW = (limit, window)    30 requests per rolling 60 s

The sliding-window counter Cloudflare described in 2017. Keep a fixed-window counter per
(address, window) as fixed_window does, but when you judge a request, blend the current
window's count with the previous window's, weighted by how far into the current window you
are:

    estimate = current + previous * (1 - elapsed_fraction)

Just after a boundary, almost all of the previous window still counts, so the burst that
beat fixed_window is now carried across the seam. It costs two counters, not a log of every
timestamp (store.Counters, the sorted-set log, is exact but O(requests) in memory); the
estimate is off by at most the traffic shape inside a window, which for rate limiting is
noise.

What it catches: the boundary burst fixed_window missed, and sustained volume from one
address, at two integer counters per address.
What it misses: the same thing every per-address limit misses: traffic spread over many
addresses.
Who it hurts: people who share an address, like any per-address limit.

This is wired as an alternative to rate_limit: pick one in ladder.py. The token bucket allows
a clean burst up to its capacity and then a smooth rate; the sliding window allows a flatter
rate with no burst credit. Run both against the boundary attack and the shoppers and read the
scoreboard.

Keys on client_ip(ctx).
"""

import time

from . import policy
from .client_ip import client_ip
from .pipeline import Check, Signal, Verdict


def estimate(redis, key, limit, window, now=None):
    """The weighted count for `key`, and whether this request fits under `limit`.

    Returns (allowed, estimate, retry_after). Pure enough for tools/limiter_lab.py to drive
    with an injected clock; it writes one counter when it allows the request.
    """
    now = time.time() if now is None else now
    slot = int(now // window)
    elapsed = (now % window) / window
    cur_k, prev_k = f"lab:rl:sw:{key}:{slot}", f"lab:rl:sw:{key}:{slot - 1}"
    cur = int(redis.get(cur_k) or 0)
    prev = int(redis.get(prev_k) or 0)
    est = cur + prev * (1 - elapsed)
    if est + 1 > limit:
        return False, est, max(1, int(window * (1 - elapsed)) + 1)
    p = redis.pipeline()
    p.incr(cur_k)
    p.expire(cur_k, 2 * window + 1)
    p.execute()
    return True, est + 1, 0


def _check(ctx):
    ip = client_ip(ctx)
    limit, window = policy.SLIDING_WINDOW
    # TODO (Round 3, if you pick this over the token bucket): judge the request with
    # estimate(ctx.redis, ip, limit, window) above and turn a refusal into a
    # Verdict("rate_limit", retry_after=..., signals=(Signal("rate_limit",
    # "sliding_window", 0, ip),)). Run it next to the bucket in tools/limiter_lab.py
    # and watch the boundary burst die.
    return None


CHECK = Check("sliding_window", _check)
