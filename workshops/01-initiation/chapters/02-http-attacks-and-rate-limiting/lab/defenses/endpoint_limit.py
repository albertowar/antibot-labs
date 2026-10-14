"""
endpoint_limit (Round 4): a tighter bucket on the endpoints that cost the most to abuse.

    policy.ENDPOINT_LIMITS = {"login": "login_ip"}    POST /login spends from login_ip too
    policy.RATE_LIMITS["login_ip"] = (10, 0.1)        10 burst, then 1 every 10 s

The per-IP bucket from Round 3 is sized for browsing: 30 a minute is nothing for a scraper
to stay under, but it is also nothing for a human reading pages. A login endpoint is
different. A person signs in once; a credential-stuffing run tries thousands of pairs. So
POST /login spends from `ip` (the general bucket) AND from a much tighter `login_ip` bucket.
A browsing session never touches login_ip; a stuffing run empties it in ten tries.

What it catches: stuffing and brute force from one address. After the burst, one try every
ten seconds is useless to an attacker and invisible to a human.
What it misses: stuffing spread over many addresses (Round 5's rotation), and a slow attacker
who tries one account per IP. It also does nothing about ONE account being hammered from many
addresses: that is account_limit's job.
Who it hurts: several people behind one NAT who all sign in at once (an office Monday morning):
the login_ip burst is shared. That is the mobile_cgnat shoppers on the scoreboard.

Keys on client_ip(ctx).
"""

from . import policy
from .client_ip import client_ip
from .pipeline import Check, Signal, Verdict

_ENDPOINTS = {"/login": "login"}


def _check(ctx):
    if ctx.method != "POST":
        return None
    name = _ENDPOINTS.get(ctx.path)
    bucket = policy.ENDPOINT_LIMITS.get(name) if name else None
    if not bucket:
        return None
    # TODO (Round 4): spend from the endpoint's own bucket — ctx.bucket(bucket,
    # client_ip(ctx)) — and when it is empty return Verdict("rate_limit",
    # retry_after=10, signals=(Signal("rate_limit", f"{bucket}_rate_limit", 0,
    # client_ip(ctx)),)). A browsing session never touches login_ip; a stuffing run
    # drains it in ten tries.
    return None


CHECK = Check("endpoint_limit", _check)
