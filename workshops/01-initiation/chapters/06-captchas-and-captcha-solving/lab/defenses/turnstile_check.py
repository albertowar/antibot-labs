"""
Chapter 6, Round 1 (L1): a provider token on sign-up and on the newsletter.

What it does: on `action:register` (POST /register, POST /api/register) and `action:newsletter`
(POST /newsletter) it takes the token the widget put in the form (`cf-turnstile-response`, in
the form body or the JSON body), redeems it through defenses/siteverify.py and blocks the
request if the token is not good. The widget itself comes from demo_site/ext/captcha.py
(slot `form:register`, plus the newsletter form in the footer).

What it catches: every bot that does not run the widget AND has no cheaper way to a token.
With a correct verifier that is a bot that buys farm-solved tokens (about $2 per 1,000).

What it misses: a bot that pays; and everything the verifier gets wrong (Round 1's four bypasses).

Who it hurts: people whose browser blocks the widget script (privacy extensions, corporate
proxies, some assistive setups), and every sign-up while the provider is down (register fails
closed). The newsletter fails open on purpose: it is a low-value endpoint.

The reason a token was refused goes to the decision log (`extra.turnstile_reason`, readable at
GET /lab/decisions), never to the client: in production an explanation is a free oracle.
"""

import time

from . import policy, siteverify
from .pipeline import Check, Signal, Verdict


def token_of(ctx):
    """The widget's token: a form field for HTML posts, a JSON key for the API."""
    if ctx.form and ctx.form.get(policy.TOKEN_FIELD):
        return ctx.form[policy.TOKEN_FIELD]
    if isinstance(ctx.json, dict):
        return str(ctx.json.get(policy.TOKEN_FIELD) or "")
    return ""


def _check(ctx):
    action = ctx.phase.split(":", 1)[1]
    t0 = time.perf_counter()
    v = siteverify.verify_token(token_of(ctx), remoteip=ctx.ip, expected_action=action,
                                expected_hostnames=policy.OUR_HOSTNAMES,
                                fail_mode=policy.TURNSTILE_FAIL_MODE.get(action, "closed"))
    ctx.note(turnstile_reason=v.reason, siteverify_ms=round((time.perf_counter() - t0) * 1000, 2))
    if v.ok:
        return None
    return Verdict("block", signals=(Signal("turnstile", "token_rejected", 100, v.reason[:60]),))


CHECK = Check("turnstile", _check, phases=("action:register", "action:newsletter"))
