"""
generic_layers: the one control the series' earlier workshops left in front of every attacker here.

The W3 starter ships with an empty baseline, so this lab adds its own Round 0: a per-IP rate limit
(W1 Ch2). It runs on every request at every level, before any scenario check, and it is deliberately
generous (500 requests per address per 10 seconds) because carrier-grade NAT puts several real shoppers
behind one address.

It is a fixed-window counter (two Redis calls) rather than the starter's token bucket on purpose: the
bucket is a Lua script, and on the in-process fakeredis a script serializes under the 16 attacker threads,
which would add ~150 ms of gate time to every shopper request and bury the cost of the checks this
chapter teaches. A fixed window lets a burst of twice the limit through at a window boundary; a token
bucket does not. Production Redis runs scripts atomically and fast, and you would use the bucket.

What it stops: one address hammering the store. What it misses, and why this chapter exists:
every attacker below rents a pool of addresses (data/world.json) and rotates per request, so no
bucket ever runs dry. Rate limiting counts requests; the five economies are not about requests.

Who it hurts: anyone behind a shared address that bursts. The limit is high enough that the 40
shoppers never meet it; lower it and the mobile_cgnat shoppers are the first to.
"""

import time

from .pipeline import Check, Signal, Verdict

LIMIT = 500          # requests per address per window
WINDOW_S = 10


def _check(ctx):
    key = f"lab:rl:ch6:{ctx.ip}:{int(time.time() // WINDOW_S)}"
    n = ctx.redis.incr(key)
    if n == 1:
        ctx.redis.expire(key, WINDOW_S * 2)
    if n <= LIMIT:
        return None
    return Verdict("rate_limit", retry_after=WINDOW_S, signals=(Signal("rate_limit", "ip", 0, f"{n} requests this window"),))


CHECK = Check("generic_ip_limit", _check)
