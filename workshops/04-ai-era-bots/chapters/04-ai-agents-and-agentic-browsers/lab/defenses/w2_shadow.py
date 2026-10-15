"""The W2 browser stack, run in SHADOW at every level. (GIVEN instrument.)

W2 Ch9 ended with this stack (automation flags, fingerprint coherence, behavior and flow) beaten by
patched and native-stealth browsers. An agent that drives a real Chromium, or the user's own Chrome,
is beyond it by construction: real GPU, real window, real TLS, real address. It runs here so you can
*see* that: `Check(shadow=True)` logs what it would have said (`X-Lab-Shadow`, the decision log) and
never decides, and the points go into the decision log's `extra.w2_shadow` for the checkpoint's
"W2 shadow" line, next to the agents and the people.
"""

from . import agent_session, automation, behavior_flow, fingerprint_coherence
from .pipeline import Check, Signal


def score(sess):
    points, reasons = 0, []
    for p, why in (automation.score_automation(sess),
                   fingerprint_coherence.score_coherence(sess["fp"], sess.get("http_ua")),
                   behavior_flow.score_behavior(sess)):
        points += p
        reasons.extend(why)
    return points, reasons


def _check(ctx):
    points, reasons = score(agent_session.state(ctx))
    ctx.note(w2_shadow=points)
    return [Signal("w2", "stack", points, "; ".join(reasons)[:140])] if points else None


CHECK = Check("w2_shadow", _check, phases=("action:drop_buy",), shadow=True)
