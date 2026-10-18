"""
blanket_otp (Round 1): every correct password must be followed by a code from the account's inbox.

defenses/stepup_policy.py calls decide(ctx) at level 1, only after a correct password. The ext
(demo_site/ext/rba.py) does the rest when you ask for the `otp` challenge: it takes the session
back, emails a six-digit code, and opens the session when the code comes back.

What it misses, and who it hurts: run the round and read the scoreboard, then the docstring of
solutions/round1/defenses/blanket_otp.py.

Reference: solutions/round1/defenses/blanket_otp.py (or `checkpoint.py --round 1 --catch-up`)
"""

from .pipeline import Signal, Verdict  # noqa: F401  (you need both)

POINTS = 50     # the challenge band


def decide(ctx):
    # TODO (Round 1): return a challenge verdict that asks for the "otp" challenge type:
    #   Verdict("challenge", challenge="otp", signals=(Signal("stepup", "every_login", POINTS, "<why>"),))
    #   Then wire defenses/stepup_policy.CHECK into LADDER[1] in defenses/ladder.py.
    return None
