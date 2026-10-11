"""
Chapter 7, Round 3 defense (L3): make a pass worth less.

At L1-L2 a solved challenge clears the whole session for ten minutes. A bot solves once
and scrapes everything. From L3 the pass is stingy, in three ways:

  budget   policy.POW_PASS_BUDGET protected requests per solve, then it is gone
  time     policy.POW_PASS_TTL seconds, shorter than the session clearance
  binding  the pass only works from the IP + User-Agent that solved it
           (recorded by pow_challenge.verify), so it cannot be handed to a farm

The challenge itself also becomes single-use at L3 (pow_challenge.verify spends the
nonce in Redis), which is what stops a bot from replaying one solution.

What it misses: a bot that simply pays for every pass (Round 3's solver pool).
Who it hurts: heavy readers. A shopper with 30 pages to look at solves twice. That is
invisible on a laptop and a few seconds on a cheap phone; pick the budget with the
slowest phone in mind, not your own.

A pass that fails any of the three is revoked, so the owner re-solves too: a stolen pass
costs the thief nothing and the owner one solve.

Cost: one Redis INCR per protected request, and a decision to write down before the
incident: if Redis is down, do you fail open or closed? This check fails closed.
"""

import time

from . import policy
from .pipeline import Check, Signal, Verdict
from .pow_gate import has_pass, protected


def client_tag(ctx):
    return f"{ctx.ip}|{ctx.ua.raw}"


def revoke(ctx):
    ctx.redis.delete(f"lab:s:{ctx.session.sid}:clear:pow")
    ctx.session.delete("cleared:pow")


def _check(ctx):
    if not protected(ctx.path) or not has_pass(ctx):
        return None                                     # no pass: pow_gate already asked for one
    reason = None
    granted = float(ctx.session.get("cleared:pow", 0) or 0)
    if time.time() - granted > policy.POW_PASS_TTL:
        reason = "pass_expired"
    elif ctx.session.get("pow:bind") != client_tag(ctx):
        reason = "pass_bound_elsewhere"
    else:
        used = ctx.redis.incr(ctx.session.ns("pow") + "used")
        ctx.redis.expire(ctx.session.ns("pow") + "used", policy.POW_PASS_TTL)
        ctx.note(pow_used=used)
        if used > policy.POW_PASS_BUDGET:
            reason = "pass_used_up"
    if reason is None:
        return None
    revoke(ctx)     # the gate downgrades a challenge while the session is cleared, so take the pass away
    ctx.note(pow_reason=reason)
    return Verdict("challenge", signals=(Signal("pow", reason, policy.POW_GATE_POINTS),), challenge="pow")


CHECK = Check("pow_budget", _check, phases=("request",))
