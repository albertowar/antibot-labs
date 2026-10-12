"""
Chapter 2: the JavaScript challenge gate (Rounds 1-5). Pre-written: read it, switch levels, measure.

What it does: a request for the catalogue (policy.JS_PROTECTED: /products and the product API)
from a session that has not passed the JavaScript challenge scores policy.JS_GATE_POINTS (a
challenge, never a block) and asks for the "js" challenge. The store answers with the
interstitial (HTML) or a 403 `challenge_required` (JSON) carrying js_challenge.issue()'s payload.

How a session passes, by level:
    1      it carries the js_ok cookie the inline script sets (cookie_gate.py)
    2-5    it holds the store's clearance for "js" (granted by POST /api/challenge/verify), and
             - the clearance was granted to this User-Agent (tokens.ua_hash), and
             - (level 5) it is younger than clearance.TTL_S and has requests left in its
               budget (clearance.BUDGET); otherwise the clearance is revoked and the next
               request is challenged again

What it catches: any client that cannot or will not run the challenge: requests, httpx, curl, a
scraper that does not read the interstitial. What it misses: anything that runs the code (a
real browser, Round 4) and anything that pays for a browser now and then (Round 5).

Who it hurts: every visitor without JavaScript, on every page behind the gate: text browsers,
hardened privacy setups, some assistive tech, API clients. The no_js shopper shows it.
"""

import time

from . import clearance, cookie_gate, js_challenge, policy, tokens
from .pipeline import Check, Signal, Verdict

CLEAR_KEY = "lab:s:{sid}:clear:js"       # what demo_site/gate.py grant_clearance() writes


def protected(path):
    return path in policy.JS_PROTECTED or any(path.startswith(p + "/") for p in policy.JS_PROTECTED)


def _challenge(ctx, why):
    return Verdict("challenge", signals=(Signal("js_gate", why, policy.JS_GATE_POINTS, ctx.path[:40]),),
                   challenge="js")


def _revoke(ctx):
    from demo_site import gate
    gate.revoke_clearance(ctx, "js")


def _check(ctx):
    if not protected(ctx.path):
        return None
    if ctx.level <= 1:
        return None if cookie_gate.passes(ctx.cookies) else _challenge(ctx, "no_cookie")
    if not ctx.redis.get(CLEAR_KEY.format(sid=ctx.session.sid)):
        return _challenge(ctx, "no_clearance")
    if ctx.session.get(js_challenge.UAH_FIELD) != tokens.ua_hash(ctx.header("User-Agent", "")):
        _revoke(ctx)
        return _challenge(ctx, "other_user_agent")
    if ctx.level >= 5:
        granted = ctx.session.get("cleared:js") or "0"
        allowed, used = clearance.consume(ctx.redis, f"{ctx.session.sid}:{granted}")
        ctx.note(jsc_budget_used=used)
        if not allowed or time.time() - float(granted) > clearance.TTL_S:
            _revoke(ctx)
            return _challenge(ctx, "budget_spent")
    return None


CHECK = Check("js_gate", _check, phases=("request",))
