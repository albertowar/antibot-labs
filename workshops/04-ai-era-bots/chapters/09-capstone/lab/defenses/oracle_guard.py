"""
W4 Ch9 Capstone — L4 the oracle guard: what a client may learn from a decision (YOUR CODE, Round 4)

Every reply about a gated action goes through shape(). Until now replies carried
the score and reasons "for teaching". W4 Ch6 showed what that teaches an
attacker: the Round 4 prober reads the score back, fits your thresholds, and
tunes a session to sit one point under the challenge band.

shape(body, decision, level) -> dict
    body      outcome, message, and what the client needs to act (challenge,
              step_up, order_id, mandate, hint, appeal, ai_disclosure)
    decision  the full risk decision (score, reasons, shadow, features)

Return only what the client needs. The score, reasons, shadow layers and level
are for the scoreboard (/admin/decisions), not the reply. /whoami stays a
loopback-only lab oracle. `tools/checkpoint.py --round 4 --catch-up` drops in
the reference.
"""

CLIENT_FIELDS = ("outcome", "message", "challenge", "step_up", "order_id", "mandate", "hint",
                 "appeal", "ai_disclosure")


def shape(body, decision, level):
    # TODO (Round 4): return only what the client needs; never the score, the
    # reasons, the shadow layers or the level.
    return {**body, "score": decision.get("score"), "reasons": decision.get("reasons", []),
            "level": level}
