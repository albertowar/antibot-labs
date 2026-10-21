"""
change_hold (Round 4): when no strong factor exists, delay instead of deny, and tell everyone who can hear.

Round 3 refuses an action when the account has no factor strong enough for it: no device, no phone, and
KBA (strength 65) does not reach an account-takeover step. Refusal strands the real owner who lost their
inbox. Round 4 does three things:

  1. KBA is demoted to a signal (policy.KBA_STRENGTH_R4): it can no longer lift a session to any weight,
     so a crew that reads the answers off the account page gains nothing, and the owners who cannot
     recall them stop failing a challenge. We stop asking it.
  2. No strong factor -> a COOLING-OFF. The check sets ctx.attrs["hold"]: the account change is stored
     `pending` (a 202), an order is held, a gift-card redemption is parked, all on the lab clock
     (policy.HOLD_HOURS: 12 h for weight 60, 24 h for weight 75). It is delayed, not denied.
  3. NOTIFY. Every sensitive action, held or applied, sends a notice with a cancel link on every channel
     the account has: the old email, the phone, the enrolled devices and an in-app banner
     (policy.NOTIFY_CHANNELS). An attacker with the webmail can purge the email; they cannot purge the
     other three. When the account has none, the email is the only channel, and the hold only buys the
     owner time if they read it.

Honest cost: every held action is a customer waiting (the scoreboard reports the median delay), and a
cooling-off protects nothing if nobody is told on a channel the attacker does not control.

Reference: solutions/round4/defenses/change_hold.py (or `checkpoint.py --round 4 --catch-up`)
"""

from . import policy, session_trust, stepup_channels, trustlib
from .pipeline import Check, Signal

STRENGTHS = {**policy.FACTOR_STRENGTH, "kba": policy.KBA_STRENGTH_R4}


def no_factor(ctx, trust, need):
    hours = policy.HOLD_HOURS[75 if need >= 75 else 60]
    ctx.attrs["hold"] = {"hours": hours, "reason": f"trust {trust:.0f} < {need} and no strong factor on file"}
    ctx.note(trust=round(trust), need=need, factor="none", hold_h=hours)
    return [Signal("trust", "cooling_off", 0, f"held {hours} h")]


def _check(ctx):
    if ctx.level < 4:
        return None
    st = ctx.attrs.get("st")
    if st is None:
        return None
    t = session_trust.trust(st, STRENGTHS)
    trustlib.restrict(ctx, t)
    need = trustlib.weight(ctx)
    if not need:
        return None
    ctx.attrs["notify_channels"] = policy.NOTIFY_CHANNELS
    if t >= need:
        return None
    factor = stepup_channels.factor_for(need, st["channels"], STRENGTHS)
    return trustlib.ask(ctx, factor, t, need) if factor else no_factor(ctx, t, need)


CHECK = Check("change_hold", _check, phases=("request", "action:*"))
