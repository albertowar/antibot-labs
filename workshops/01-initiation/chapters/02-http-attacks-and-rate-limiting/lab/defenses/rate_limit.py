"""
rate_limit: a per-IP token bucket on every request.

    policy.RATE_LIMITS["ip"] = (capacity, refill/s)    20 burst, 0.5/s = 30 requests a minute

A token bucket allows a burst (capacity), then a sustained rate (refill per second). The
check-and-take is one Lua script (defenses/store.py), so concurrent requests can't both
spend the last token. POST /checkout also spends from a tighter `checkout_ip` bucket.

What it catches: volume from one address. A scraper on one cloud VM gets its burst, then
one page every two seconds. Unlike a fixed window, there is no boundary to burst across:
the bucket refills continuously.
What it misses: anything spread over many addresses. A proxy list, a fleet of VMs, or a
fresh IPv6 address for every request (one /64 holds 18 quintillion of them) each send a
handful of requests per address and never touch the limit. So does a patient client that
stays just under 30 a minute from one address.
Who it hurts: people who share an address. Carrier-grade NAT puts a neighbourhood of phones
behind one IPv4 address, and a limit sized for one person throttles all of them. The
mobile_cgnat shoppers show it on the scoreboard.

Keys on client_ip(ctx), so until `trusted_proxy` is wired a forged X-Forwarded-For picks
the bucket. Internal addresses are not exempt: a client claiming to be 127.0.0.1 shares
one bucket with every other client claiming the same.
"""

from .client_ip import client_ip
from .pipeline import Check, Signal, Verdict


def _check(ctx):
    ip = client_ip(ctx)
    # TODO (Round 3): spend one token from the "ip" bucket — ctx.bucket("ip", ip) is the
    # atomic check-and-take, sized by policy.RATE_LIMITS — and on POST /checkout spend
    # from the tighter "checkout_ip" bucket too. The first empty bucket is a
    # Verdict("rate_limit", retry_after=2, signals=(Signal("rate_limit",
    # f"{bucket}_rate_limit", 0, key),)). Shared with Chapter 3: its lab starts from the
    # reference version of this file.
    return None


CHECK = Check("rate_limit", _check)
