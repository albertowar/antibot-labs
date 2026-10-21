"""
recovery_risk (Round 3): a password reset is a login. Score it like one.

Every account has a second way in: "forgot your password?". It proves one thing, access to the
inbox, and on most sites it skips everything Round 2 built: no history, no device, no band. So an
attacker who owns the victim's email account (this round's crew holds nothing else) resets the
password, signs in, and answers the emailed code from the same inbox. One channel, two "factors".

The defense scores the request that CONFIRMS the reset (it carries the new password) with the
Round 2 model, against the account's history:

    low     the account's own remembered device on a familiar network: apply it now
    medium  unfamiliar: park it for policy.COOLING_OFF_H hours and tell the account holder on every
            channel the store knows (the ext emails and notifies the remembered devices); the owner
            can cancel, the attacker has to wait and hope nobody reads the notice
    high    refuse outright

Why delay instead of a stronger prompt? Because the customer who forgot their password usually has
nothing stronger to offer, and a code to the same inbox proves nothing new. Time is the factor the
attacker cannot buy: a waiting period turns a silent takeover into a race against the owner reading
one email. Large providers do the same for recoveries from unfamiliar devices.

What it misses: an attacker who also holds the remembered-device cookie scores "low" here too (the
Round 2 hole), and an attacker who never needs the reset (the mailbox crew, password in hand).
Both are where phishing-resistant factors come in (§5.6, theory).

Who it hurts: the honest customer who forgot their password on a new phone. They wait three days,
and the store needs a support path for the urgent cases (§5.7). That is the `forgot_new_phone`
cost the checkpoint reports.
"""

from . import policy, rba_score
from .pipeline import Check, Signal, Verdict


def _check(ctx):
    rec = ctx.attrs.get("recovery")
    if not rec:
        return None
    total, parts = rba_score.score(rec["features"], rec["hist"], rec["glob"], rec["net"])
    band = rba_score.band(total, rec["hist"])
    ctx.note(recovery_score=round(total, 2), recovery_band=band)
    if band == "high":
        return Verdict("block", signals=(Signal("recovery", "refused", 100, f"score {total:.1f}"),))
    if band == "medium":
        ctx.attrs["recovery_hold_h"] = policy.COOLING_OFF_H
        return [Signal("recovery", "cooling_off", 0, f"score {total:.1f}: held {policy.COOLING_OFF_H} h")]
    return None


CHECK = Check("recovery_risk", _check)
