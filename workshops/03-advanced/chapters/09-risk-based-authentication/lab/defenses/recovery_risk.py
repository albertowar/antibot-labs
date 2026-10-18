"""
recovery_risk (Round 3): a password reset is a login. Score it like one.

"Forgot your password?" proves one thing, access to the inbox, and skips everything Round 2 built.
This check runs in the request phase of every gated request and acts only on
`POST /api/password-reset/confirm`, where demo_site/ext/rba.py has put the confirming request's
context in ctx.attrs["recovery"]: {"uid", "features", "hist", "glob", "net"}, the same shape as
a login's ctx.attrs["rba"].

Score it with your Round 2 model (rba_score.score, rba_score.band) and answer:

    low     return None: the reset applies now
    medium  set ctx.attrs["recovery_hold_h"] = policy.COOLING_OFF_H and return
            [Signal("recovery", "cooling_off", 0, "<why>")]: the ext parks the reset, answers 202
            and notifies the account holder
    high    return Verdict("block", signals=(Signal("recovery", "refused", 100, "<why>"),))

Reference: solutions/round3/defenses/recovery_risk.py (or `checkpoint.py --round 3 --catch-up`)
"""

from . import policy, rba_score  # noqa: F401  (you need both)
from .pipeline import Check, Signal, Verdict  # noqa: F401


def _check(ctx):
    rec = ctx.attrs.get("recovery")
    if not rec:
        return None
    # TODO (Round 3): score `rec` with rba_score and return the answer for its band (see above).
    #   Then wire CHECK into LADDER[3] in defenses/ladder.py.
    return None


CHECK = Check("recovery_risk", _check)
