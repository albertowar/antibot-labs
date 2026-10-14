"""
W1 Ch5 — Round 1: trust the server, not the cookie.

The store ships a promo whose "unlocked" flag lives in a signed client-side cookie
(demo_site/ext/promo.py). A signature proves the server wrote that cookie once; it
does NOT prove it is the latest copy. So a bot solves the quiz once, snapshots the
cookie, and replays it for a fresh voucher every time.

This check moves the decision to the server session and spends it exactly once:
    - `/promo/unlock` sets `promo_ok` in the Redis session hash;
    - this check, on the redeem action, consumes it with a single HDEL.

An HDEL that removed a field returns 1; a second HDEL for the same field returns 0.
That one Redis op is the whole fix: the first redeem in the unlocked session passes,
every replay (a fresh session, or the same session a second time) is blocked.

What it catches: cookie replay and session sharing of the "solved" flag.
What it misses: a bot that genuinely unlocks each session (Round 2 rate-limits that).
False positives: none. A human unlocks, then redeems once, in the same session.
"""

from .pipeline import Check, Signal, Verdict


def _check(ctx):
    s = ctx.session
    if not s.get("promo_ok"):
        return Verdict("block", 100, (Signal("promo_state", "promo_not_unlocked", 100,
                       "redeem from a session the server never saw unlock"),))
    # Atomic single-use: HDEL returns 1 the first time, 0 for every replay of the same session.
    if not ctx.redis.hdel(s.key, "promo_ok"):
        return Verdict("block", 100, (Signal("promo_state", "promo_replayed", 100,
                       "the unlock for this session was already spent"),))
    return None


CHECK = Check("promo_state", _check, phases=("action:promo_redeem",))
