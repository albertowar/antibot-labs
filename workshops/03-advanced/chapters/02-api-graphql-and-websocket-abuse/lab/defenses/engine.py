"""Risk engine: one score, three outcomes, five layers keyed to the rounds.

The same additive 0–100 scale Workshop 2 settled on (W2 Ch8/Ch9):

    score <  30   allow
    score 30–59   challenge
    score >= 60   block

Each layer returns (points, [reasons]). A layer runs when DEFENSE_LEVEL >= its
level; below that it runs in *shadow mode* — points are logged in
decision["shadow"] but do not count — which is how you roll a new API defense
out against real traffic before it can block anyone.

    Level  Tag  Surface   Module                         Round
    1      L1   REST      rate_cost                      1
    2      L2   GraphQL   graphql_limits                 2
    3      L3   GraphQL   persisted_queries              3
    4      L4   WS        ws_guard (handled in app.py)   4
    5      L5   REST      request_signing + token_binding 5

Additive points, not a probability: easy to read in a reason list and easy to
tune in a lab. The cost is that correlated signals double-count; keep each
layer's points sized so any single real violation blocks on its own.
"""

from __future__ import annotations

ALLOW_BELOW = 30
BLOCK_AT = 60


def outcome_for(score: float) -> str:
    if score >= BLOCK_AT:
        return "block"
    if score >= ALLOW_BELOW:
        return "challenge"
    return "allow"


def combine(layers, level, base=None):
    """layers: [(min_level, tag, (points, reasons))]. Returns a decision dict."""
    score = base["score"] if base else 0
    reasons = list(base["reasons"]) if base else []
    shadow = dict(base["shadow"]) if base else {}
    for min_level, tag, (points, why) in layers:
        if level >= min_level:
            score += points
            reasons.extend(f"[{tag}] {r}" for r in why)
        elif points:
            prev = shadow.get(tag, {"points": 0, "reasons": []})
            shadow[tag] = {"points": prev["points"] + points,
                           "reasons": prev["reasons"] + list(why)}
    score = min(score, 100)
    return {"score": score, "outcome": outcome_for(score), "reasons": reasons, "shadow": shadow}
