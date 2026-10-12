"""
Chapter 5, Round 2 (L2): an image CAPTCHA in front of the promo voucher, and the glue around it.

The store (demo_site/ext/captcha.py) registers a challenge type `captcha` whose issue() and
verify() live here. This module is the part of the defense that is NOT one of your four
student files; it calls them:

    challenge_store   Round 2: where the answer lives         (issue / check)
    captcha_generator Round 3: the image                      (new_challenge)
    solver_signals    Round 4: solve signals + serve on risk  (assess / note_failure)

What it does: a redemption (`action:promo_redeem`, POST /lab/promo/redeem) from a session that has
not just solved a CAPTCHA scores CAPTCHA_POINTS and asks for the `captcha` challenge. The gate
turns that into a 403 (JSON `challenge_required` with the image in the payload, or the interstitial
page). The client fetches/answers it at GET /api/challenge?type=captcha and POST
/api/challenge/verify {"type": "captcha", "answer": {"id", "text"}}; a correct answer clears the
session for exactly ONE redemption (`uses=1` in demo_site/ext/captcha.py). At L4 this check steps
aside and solver_signals.CHECK serves the CAPTCHA only to risky sessions.

What it catches: any client that cannot read the image. What it misses: everything with a solver
(Round 3's OCR, Round 4's farm). Who it hurts: everyone who has to solve it, and people who cannot
see or read the image at all (screen-reader users; there is no audio or alternative path in this
lab: that is the false positive the chapter wants you to see on the scoreboard).

Defender cost: demo_site/ext/captcha.py times issue() and verify() and adds them to the gate figure
(`captcha_gen_ms`, `captcha_check_ms` in the decision log's extra).

Lab-only: issue() also writes the answer to lab:eyes:<id> so simulated humans and the simulated
farm can "read" the image (GET /lab/captcha/eyes/<id>). A bot script must never call that.
"""

import base64
import time

from . import captcha_generator, challenge_store, policy, solver_signals
from .pipeline import Check, Signal, Verdict


def style_for(level):
    return "hardened" if level >= policy.HARDENED_FROM_LEVEL else "basic"


def issue(ctx):
    """The challenge payload: a PNG as a data URI plus its id. The answer never travels in it."""
    answer, png = captcha_generator.new_challenge(style_for(ctx.level))
    cid, cookie = challenge_store.issue(ctx, answer)
    ctx.redis.set(f"lab:eyes:{cid}", answer, ex=600)               # LAB ONLY: simulated eyes
    if cookie:                                  # the shipped (Round 2) design; demo_site/ext/captcha.py sets it
        ctx.attrs["captcha_cookie"] = cookie
    return {"id": cid, "image": "data:image/png;base64," + base64.b64encode(png).decode()}


def verify(ctx, answer):
    """Check a submitted answer. Returns (ok, reason); the reason goes to the log, not the client."""
    answer = answer if isinstance(answer, dict) else {}
    ok, reason, record = challenge_store.check(ctx, str(answer.get("id", "")), str(answer.get("text", "")),
                                               ctx.cookies.get(challenge_store.COOKIE_NAME))
    solve_sim = (time.time() - record["issued_at"]) * policy.TIME_SCALE if record else -1.0
    ctx.note(captcha_reason=reason, captcha_correct=ok, solve_sim=round(solve_sim, 2), ip_match=bool(record) and record.get("issuer_ip") == ctx.ip)
    if not ok:
        ctx.session.incr("captcha_failures")
        if ctx.level >= 4:
            solver_signals.note_failure(ctx)
        return False, reason
    if ctx.level >= 4:
        d = solver_signals.assess(ctx, record, solve_sim)
        ctx.note(captcha_assess=d.action, captcha_reason="; ".join(d.reasons) or reason)
        if d.action != "allow":
            ctx.session.incr("captcha_failures")
            solver_signals.note_failure(ctx)
            return False, d.action
    return True, reason


def _check(ctx):
    if ctx.level >= 4:
        return None                    # Round 4: solver_signals.CHECK serves the CAPTCHA on risk, not on every redemption
    return Verdict("challenge", signals=(Signal("captcha", "every_redemption", policy.CAPTCHA_POINTS, "promo voucher"),),
                   challenge="captcha")


CHECK = Check("captcha_gate", _check, phases=("action:promo_redeem",))
