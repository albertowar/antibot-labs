"""
session_trust (Round 2): a number with a half-life, compared with the weight of what the session asks for.

The Chapter 5 login granted a starting trust (70 on a known device and network, 45 on the remembered-device
cookie alone, 55 after an emailed code, 40 on a cold start; demo_site/ext/session_trust.py stamps it).
This module turns that stamp, plus what has happened since, into one number:

    trust = max( login_base x (1 - age / AGE_LIMIT) x (1 - idle / IDLE_LIMIT) - drift,   the login, decayed
                 strongest solved step-up factor that is still inside FACTOR_TTL_S )     what was earned since

  * It DECAYS with the session's age and with idle time. The limits are NIST SP 800-63B-4's AAL2
    reauthentication recommendations (24 h overall, 1 h inactivity; both SHOULD) divided by the lab
    clock (policy.LAB_CLOCK_DIVISOR).
  * It DROPS on drift: the network (ASN) or the browser changed since the session started.
  * It RISES only when a step-up factor is solved, and only up to that factor's strength. Time and
    browsing never raise it: policy.TRUST_AGE_BONUS_PER_MIN is 0, and the lab shows what a non-zero
    value costs (attacks/round2_inbox_code.py --patient).

Round 2's first model treats any second factor as strong: a password re-entry earns 55 and a code to the
on-file email earns 80. Round 3 asks whether email deserves that.

Reference: solutions/round2/defenses/session_trust.py (or `checkpoint.py --round 2 --catch-up`)
"""

from . import policy, trustlib
from .pipeline import Check

FIRST_MODEL = {"sudo": 55, "otp_session": 80}


def trust(st, strengths=None):
    strengths = strengths or FIRST_MODEL
    age, idle = st["login_age_s"], st["idle_s"]
    base = st["login_base"] * (1 - min(1.0, age / policy.TRUST_AGE_LIMIT_S)) * (1 - min(1.0, idle / policy.TRUST_IDLE_LIMIT_S))
    base += policy.TRUST_AGE_BONUS_PER_MIN * min(age, policy.TRUST_AGE_LIMIT_S) / (60 / policy.LAB_CLOCK_DIVISOR)
    base -= sum(policy.DRIFT_PENALTY[k] for k, drifted in st["drift"].items() if drifted)
    earned = [strengths.get(f, 0) for f, since in st["factors"].items() if since <= policy.FACTOR_TTL_S]
    return max(0.0, base, float(max(earned, default=0)))


def factor_for(need):
    """The cheapest factor of the first model that reaches `need`, or None."""
    for f, strength in sorted(FIRST_MODEL.items(), key=lambda kv: kv[1]):
        if strength >= need:
            return f
    return None


def _check(ctx):
    if ctx.level != 2:
        return None
    st = ctx.attrs.get("st")
    if st is None:
        return None
    t = trust(st)
    trustlib.restrict(ctx, t)
    need = trustlib.weight(ctx)
    if not need or t >= need:
        return None
    factor = factor_for(need)
    return trustlib.ask(ctx, factor, t, need) if factor else trustlib.refuse(ctx, t, need, "no_factor")


CHECK = Check("session_trust", _check, phases=("request", "action:*"))
