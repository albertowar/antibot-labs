"""Round 1 defense (REFERENCE SOLUTION) — breached-credential gate at login.

Economic chokepoint: the stuffer only has *breached* passwords to try. So gate on
that fact. A login whose password is correct AND in the breach corpus does not get
a bare session: it is sent to a forced reset / step-up (CHALLENGE). Every stuffing
hit uses a breached password, so every hit converts to friction instead of a
takeover — without the defender ever needing to know the attempt was a bot.

False positive, named honestly: a real user who reused a breached password gets the
same one-time reset prompt. That is a cost. It is small and self-correcting (they
reset once), but it is real, and it is why this belongs at login step-up and at
password-set time, not as a silent block.
"""

from __future__ import annotations

from store import allow, challenge, Decision, INVALID


def evaluate(ctx) -> Decision:
    if not ctx["valid_creds"]:
        return Decision(INVALID, 0.0, "bad credentials")
    if ctx["breach"].is_breached(ctx["password"]):
        return challenge("breached password -> forced reset", score=100.0)
    return allow("clean password")
