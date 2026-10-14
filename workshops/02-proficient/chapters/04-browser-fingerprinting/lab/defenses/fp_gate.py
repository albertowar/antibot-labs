"""
Chapter 4 — L1a: a sign-up needs a fingerprint (Section 4.3, Round 1).

From level 1, `POST /register` and `POST /api/register` need a fingerprint
record for the session: the collector ran on the sign-up page and posted a
payload with this session's nonce. A client that never runs the page's
JavaScript has none: raw HTTP sign-up scripts, and real people who block or
disable JavaScript.

    rule                    points  why
    no fingerprint record   40      no valid POST /api/telemetry {"kind": "fp"} for this session

40 is a refusal in this lab's bands (defenses/policy.py). That is the price of
a JavaScript gate: the no-JavaScript shopper is refused from Round 1 on, and
the checkpoint counts it as an accepted, measured cost (`allowed_fp`). In
production you would send those users to a challenge (W1 Ch6) rather than a 403.

This check runs on the sign-up action, not on every request: the page that
serves the collector must stay open, or nobody could ever get a fingerprint.

What it does not stop: a client that skips the browser and posts a believable
payload itself. That is exactly what Round 3 does, and why the later layers
judge consistency and reuse instead of mere presence. Making the collector
itself hard to replay is Chapter 2.
"""

from .pipeline import Check, Signal

NO_FINGERPRINT_POINTS = 40


def evaluate(ctx):
    """(points, reasons): 40 if this session has no fingerprint record."""
    from . import fingerprint
    if fingerprint.record(ctx) is not None:
        return 0, []
    return NO_FINGERPRINT_POINTS, ["No fingerprint for this session (the collector never ran)"]


def _check(ctx):
    points, reasons = evaluate(ctx)
    if not points:
        return None
    ctx.notes.setdefault("fp_reasons", []).extend(f"[L1] {r}" for r in reasons)
    return [Signal("fp", "no_fingerprint", points, reasons[0])]


CHECK = Check("fp_gate", _check, phases=("action:register",))
