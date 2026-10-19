"""
W1 Ch8 — Round 2: limit session creation, not just sessions.

Round 1 backed the voucher by server-side state, so a bot can no longer reuse one
unlock. Its answer is to create a fresh session for every voucher: drop the cookie,
unlock again, redeem again. A per-session limit resets for free when the session does.

So we rate-limit the thing underneath: how fast one IP mints brand-new sessions. A
real visitor creates one session and keeps it. A reset bot (and any cookieless client,
which gets a new session on every request) creates them far faster than a person.

Fixed one-minute window per IP, the same shape as Chapter 2's rate limit. We use a
plain Redis INCR here, not the token bucket, so the lab runs on bare fakeredis.

What it catches: session-reset and cookieless bots from one address.
What it misses: a bot that rotates IPs (one new session per address looks human) — the
    red step shows it, and later layers read the session itself, not its birth rate.
False positives: many people behind one address. A carrier-NAT block, an office or a
    university can mint sessions faster than the limit. `MAX_NEW_SESSIONS_PER_MIN` is
    tuned above the busiest shared address in the shopper population; the README's blue
    stretch lowers it to 3 and shows the mobile_cgnat phones get caught.
"""

import time

from . import policy
from .pipeline import Check, Signal, Verdict


def _check(ctx):
    if not ctx.session.new:
        return None
    key = f"lab:sessvel:{ctx.ip}:{int(time.time() // 60)}"
    n = ctx.redis.incr(key)
    ctx.redis.expire(key, 120)
    if n > policy.MAX_NEW_SESSIONS_PER_MIN:
        return Verdict("rate_limit", 0, (Signal("session_velocity", "new_session_flood", 0,
                       f"{n} new sessions in a minute from {ctx.ip}"),), retry_after=30)
    return None


CHECK = Check("session_velocity", _check, phases=("request",))
