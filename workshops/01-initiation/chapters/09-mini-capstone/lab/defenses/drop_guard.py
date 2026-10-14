"""
drop_guard: the capstone's own glue. Five checks that point the chapters' defenses at the drop.

Chapters 2, 5 and 8 each built a defense for the page they were teaching: Chapter 2's rate limit
meters POST /checkout, Chapter 5's session guard fires on the promo redeem, Chapter 8's traps sit on
the signup form. The drop buys through POST /drop/<sku> (and POST /api/buy), so the capstone does not
copy and edit those modules (copies drift). It re-points them:

    RATE_CHECK      Chapter 2's checkout bucket (policy.RATE_LIMITS["checkout_ip"]) on the drop POST
    FORM_CHECK      Chapter 8's honeypot and timing token on the drop form, using form_traps'
                    own helpers (honeypot_name, _sign) and responses.on_hit for the answer
    SESSION_CHECK   Chapter 5's session_guard signals, same function, phase action:drop_buy
    BINDING_CHECK   Chapter 5's binding signals (UA hash, ASN), same function, phase action:drop_buy
    CAP_CHECK       one hoodie per customer: the session has bought, so the next buy is refused

The checks that need no re-pointing (rate_limit, prefix_limit, the header checks, ip_reputation,
crawl_traps, the PoW gate) are wired straight from their modules in ladder.py.

All five run in the `action:drop_buy` phase, which the drop routes enter just before an irreversible
step (demo_site/routes/pages.py, api.py: `guard("drop_buy")`). That phase decides on ITS OWN signals:
the request phase already ran, but its points do not carry over.

Trade-offs:
  - The one-per-customer cap is per SESSION, because only logged-in accounts have a cap in the store
    (`max_per_account`), and a bot that drops its cookies starts clean. What makes a fresh session
    expensive is everything else in the ladder (a proof of work per session, a session that must look
    old enough, a trap it must not touch). The cap alone proves nothing.
  - A rate limit per IP stops one client; the carrier-NAT shoppers share one IP (policy.RATE_LIMITS).
"""

import hmac
import time

from . import form_traps, policy, responses
from .client_ip import client_ip
from .pipeline import Check, Signal, Verdict
from .session_guard import _binding, _signals as _session_signals

DROP_ACTION = ("action:drop_buy",)


def _drop_form_post(ctx):
    """The HTML drop form (POST /drop/<sku>). /api/buy is JSON and carries no form fields."""
    return ctx.method == "POST" and ctx.path.startswith("/drop/")


def _rate(ctx):
    if not ctx.bucket("checkout_ip", client_ip(ctx)):
        return Verdict("rate_limit", retry_after=2,
                       signals=(Signal("rate_limit", "checkout_ip_rate_limit", 0, client_ip(ctx)),))
    return None


def _form(ctx):
    """Chapter 8's two form traps, read back from the drop form."""
    if not _drop_form_post(ctx):
        return None
    sid = ctx.session.sid
    name = form_traps.honeypot_name(sid, ctx.level)
    if ctx.form.get(name, "").strip():
        return responses.on_hit(ctx, "form_traps", "honeypot_field", f"{name} was filled", form=True)
    issued, _, sig = ctx.form.get("ts", "").partition(".")
    if not issued.isdigit() or not hmac.compare_digest(sig, form_traps._sign(f"{sid}:{issued}")[:16]):
        return responses.on_hit(ctx, "form_traps", "timing_token_missing", "no valid ts", form=True)
    elapsed = time.time() - int(issued) / 1000
    ctx.note(fill_seconds=round(elapsed, 2))
    if elapsed < policy.MIN_FILL_SECONDS:
        return responses.on_hit(ctx, "form_traps", "too_fast", f"{elapsed:.2f}s", form=True)
    return None


def _cap(ctx):
    cap = policy.PURCHASES_PER_SESSION
    if cap and int(ctx.session.get("drop_purchases", 0) or 0) >= cap:
        return Verdict("block", signals=(Signal("limit", "one_per_customer", 100,
                                                f"this session already bought {cap}"),))
    return None


RATE_CHECK = Check("drop_rate", _rate, phases=DROP_ACTION)
FORM_CHECK = Check("drop_form_traps", _form, phases=DROP_ACTION)
SESSION_CHECK = Check("session_guard", _session_signals, phases=DROP_ACTION)
BINDING_CHECK = Check("session_binding", _binding, phases=DROP_ACTION)
CAP_CHECK = Check("one_per_customer", _cap, phases=DROP_ACTION)


if __name__ == "__main__":
    for c in (RATE_CHECK, FORM_CHECK, SESSION_CHECK, BINDING_CHECK, CAP_CHECK):
        print(f"{c.name:<18} phases={c.phases}")
