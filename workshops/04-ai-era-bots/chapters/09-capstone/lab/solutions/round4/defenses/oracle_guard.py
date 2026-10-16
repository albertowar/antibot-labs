"""
W4 Ch9 Capstone — L4 the oracle guard (REFERENCE SOLUTION, Round 4)

Every JSON reply about a gated action passes through shape(). Below L4 the reply
carries the score, the reasons and the level "for teaching" — and W4 Ch6 showed
what that teaches an attacker: the Round 4 prober reads the score back, fits the
challenge threshold and tunes a session to sit one point under it. At L4 the
guard strips exactly those fields and nothing else.

A decision tells the client the outcome and what to do next (the `error` block
with its challenge payload, the order, the mandate, the appeal link, the AI
disclosure); it never tells the client which layer fired, how many points it
has, or how close it sits to a threshold. So this is a denylist of the four
fields that describe HOW the decision was made, not an allowlist of reply keys:
a whitelist would have to be revised every time a route adds a field, and the
day it misses one it silently breaks that route for every client.

What this does not stop: an attacker can still measure outcomes (allow /
challenge / block) and fit thresholds far more slowly, with many more accounts.
That is what the per-account and per-device caps, the velocity rule and W4 Ch6's
robust training are for. The guard turns a 200-request probe into a 2,000-account
one.
"""

# The fields that describe how the decision was made — never sent to the client at L4.
LEAK_FIELDS = ("score", "reasons", "level", "shadow", "signals", "features")


def shape(body, decision, level):
    if level < 4:
        # the leak the prober exploits: the score and reasons ride along with the reply
        return {**body, "score": decision.get("score"), "reasons": decision.get("reasons", []),
                "level": level}
    return {k: v for k, v in body.items() if k not in LEAK_FIELDS}
