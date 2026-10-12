"""
Round 1: a per-IP token bucket on every request (Chapter 1's limit, carried over).

    policy.RATE_LIMITS["ip"] = (capacity, refill/s)    20 burst, 0.5/s = 30 requests a minute

A token bucket allows a burst (capacity), then a sustained rate (refill per second). The
check-and-take is one Lua script (defenses/store.py), so concurrent requests can't both
spend the last token. POST /checkout also spends from a tighter `checkout_ip` bucket.

What it catches: volume from one address. A scraper on one cloud VM gets its burst, then
one page every two seconds.
What it misses: anything spread over many addresses. Round 2's proxies, Round 3's fleet of
VMs and Round 1's own IPv6 variant (a fresh address in the same /64 for every request) each
send a handful of requests per address and never touch the limit.
Who it hurts: people who share an address. Carrier-grade NAT puts a neighbourhood of phones
behind one IPv4 address, and a limit sized for one person throttles all of them. The
mobile_cgnat shoppers show it on the scoreboard.

Keys on client_ip(ctx), so until Round 4 a forged X-Forwarded-For picks the bucket. Internal
addresses are not exempt: a client claiming to be 127.0.0.1 shares one bucket with every
other client claiming the same.
"""

from .client_ip import client_ip
from .pipeline import Check, Signal, Verdict


def _check(ctx):
    ip = client_ip(ctx)
    buckets = [("ip", ip)]
    if ctx.method == "POST" and ctx.path == "/checkout":
        buckets.append(("checkout_ip", ip))
    for bucket, key in buckets:
        if not ctx.bucket(bucket, key):
            return Verdict("rate_limit", retry_after=2,
                           signals=(Signal("rate_limit", f"{bucket}_rate_limit", 0, key),))
    return None


CHECK = Check("rate_limit", _check)
