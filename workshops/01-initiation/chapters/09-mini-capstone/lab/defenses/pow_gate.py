"""
Chapter 6, Round 1 defense (L1): a proof-of-work gate on the catalog.

What it does: a request for a catalog page (policy.POW_PROTECTED) from a session that
has not solved a challenge scores POW_GATE_POINTS and asks for the `pow` challenge.
The policy turns that into a 403 interstitial (HTML) or `challenge_required` (JSON);
the page's own JavaScript (demo_site/static/js/pow.js) solves it, posts the answer to
POST /api/challenge/verify, and the session is cleared for policy.CLEARANCE_TTL seconds.

What it catches: any client that cannot or will not run the solver: curl, requests,
httpx, a scraper that does not read the interstitial.

What it misses: anything that pays (Rounds 3-5), and anything that cheats the puzzle
(Round 1's forged difficulty beats the naive verifier in pow_challenge.py).

Who it hurts: every visitor without JavaScript (text browsers, hardened privacy
setups, some assistive tech, API clients), on every page behind the gate. That is the
price of any JS-only control. The `no_js` shopper shows it on the scoreboard.

Trade-off: the pass is the session's clearance, so one solve buys everything behind
the gate until it expires. Round 2's attack lives in that sentence.
"""

from . import policy
from .pipeline import Check, Signal, Verdict


def protected(path):
    return path.startswith(policy.POW_PROTECTED) or path in policy.POW_PROTECTED


def has_pass(ctx):
    """The gate's clearance key, the same one demo_site/gate.py writes on a verified answer."""
    return bool(ctx.redis.get(f"lab:s:{ctx.session.sid}:clear:pow"))


def _check(ctx):
    if not protected(ctx.path) or has_pass(ctx):
        return None
    return Verdict("challenge", signals=(Signal("pow", "no_pass", policy.POW_GATE_POINTS, ctx.path[:40]),),
                   challenge="pow")


CHECK = Check("pow_gate", _check, phases=("request",))
