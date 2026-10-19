"""
stepup_policy: the one check that turns "the password was right" into allow, a step-up or a refusal.
(Finished: you write the modules it calls.)

It runs in `action:login_result` (demo_site/ext/rba.py), only on a correct password, after W2 Ch6's
breach screen (LADDER[0]). It is wired at LADDER[1] and branches on the level, because each round
replaces the previous round's rule rather than adding to it:

    level 1   blanket_otp.decide(ctx): every login proves the inbox            (Round 1, your file)
    level 2+  rba_score: how unusual is this login for this account?          (Round 2, your file)
                low     allow: step down, no prompt
                medium  challenge "otp": step up with an emailed code
                high    block: refuse, with no prompt an attacker could farm or relay

A step-up is a Verdict("challenge", challenge="otp"): the ext takes the session back, emails the
code, and opens the session only when the code comes back to the same session that typed the
password. A refusal is a hard block, answered like any other 403.

The score, the band and each feature's contribution go to the decision log (`extra.rba_*`), so a
support agent can answer "why was I asked for a code?" from the log alone.
"""

from . import blanket_otp, rba_score
from .pipeline import Check, Signal, Verdict

STEP_UP_POINTS = 50     # the policy's challenge band


def _check(ctx):
    login = ctx.attrs.get("login")
    if not login or not login["ok"] or ctx.user is None or ctx.attrs.get("stepup"):
        return None                       # failed logins keep their 401; a breached password already stepped up
    if ctx.level < 2:
        return blanket_otp.decide(ctx)
    rba = ctx.attrs["rba"]
    total, parts = rba_score.score(rba["features"], rba["hist"], rba["glob"], rba["net"])
    band = rba_score.band(total, rba["hist"])
    ctx.note(rba_score=round(total, 2), rba_band=band, rba_parts={k: round(v, 2) for k, v in parts.items()})
    if band == "high":
        return Verdict("block", signals=(Signal("rba", "high_risk", 100, f"score {total:.1f}"),))
    if band == "medium":
        ctx.attrs["stepup"] = True
        return Verdict("challenge", challenge="otp",
                       signals=(Signal("rba", "unfamiliar_login", STEP_UP_POINTS, f"score {total:.1f}"),))
    return None


CHECK = Check("stepup_policy", _check, phases=("action:login_result",))
