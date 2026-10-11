"""
W4 Ch9 Capstone — L4 the oracle guard (REFERENCE SOLUTION, Round 4)

A decision is an allowlist of fields, not a redaction of the debug reply. The
client learns the outcome and what it needs to do next; never which layer
fired, how many points it has, or how close it sits to a threshold. Two
things that are deliberately kept: the appeal link (a block a person cannot
contest is an Article 22 problem, W3 Ch8) and the challenge details (a
challenge you cannot answer is a block).

What this does not stop: an attacker can still measure outcomes (allow /
challenge / block) and fit thresholds more slowly, with many more sessions.
That is what the per-account and per-device caps, the velocity rule and W4
Ch6's robust training are for. The guard turns a 200-request probe into a
2,000-account one.
"""

CLIENT_FIELDS = ("outcome", "message", "challenge", "step_up", "order_id", "mandate", "hint",
                 "appeal", "ai_disclosure")


def shape(body, decision, level):
    return {k: v for k, v in body.items() if k in CLIENT_FIELDS}
