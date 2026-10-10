"""
W3 Ch1 — Risk engine: one score, three outcomes (reused scale from W2 Ch8/Ch9)

The additive 0-100 scale the whole series settles on:

    score <  30   allow
    score 30-59   challenge   (step-up: re-attest, emailed code, queue)
    score >= 60   block

Each layer returns (points, [reasons]). A layer is enabled when
DEFENSE_LEVEL >= its level. Disabled layers still run in *shadow mode*: their
points go into decision["shadow"] and the decisions table, but not into the
score, so you can measure what a new layer would do to real traffic before it
can hurt anyone.

    Level  Tag  Where            Module
    0      L0   every request    request_checks (app shape, per-egress rate)
    1      L1   mobile buy       attestation       (valid provider verdict?)
    2      L2   mobile buy       request_signing   (bound to this request, fresh, not replayed)
    3      L3   mobile buy       device_verdict    (integrity level + device/egress velocity)

Round 1's defence is certificate pinning, which lives in the CLIENT
(defenses/pinned_client.py), not here: it decides whether the attacker can read
the API at all, before any server-side scoring happens.
"""

import attestation
import device_verdict
import request_checks
import request_signing

ALLOW_BELOW = 30
BLOCK_AT = 60


def outcome_for(score):
    if score >= BLOCK_AT:
        return "block"
    if score >= ALLOW_BELOW:
        return "challenge"
    return "allow"


def combine(layers, level, base=None):
    """layers: [(min_level, tag, (points, reasons))]. Returns a decision dict."""
    score = base["score"] if base else 0
    reasons = list(base["reasons"]) if base else []
    shadow = {}
    for min_level, tag, (points, why) in layers:
        if level >= min_level:
            score += points
            reasons.extend(f"[{tag}] {r}" for r in why)
        elif points:
            shadow[tag] = {"points": shadow.get(tag, {}).get("points", 0) + points,
                           "reasons": shadow.get(tag, {}).get("reasons", []) + why}
    score = min(score, 100)
    return {"score": score, "outcome": outcome_for(score), "reasons": reasons, "shadow": shadow}


def score_request(ctx, store, level, count=True):
    """L0 checks that need only the HTTP request (run on every request)."""
    return combine([
        (0, "L0", request_checks.score_headers(ctx)),
        (0, "L0", request_checks.score_rate(ctx, store, count=count)),
    ], level)


def evaluate_buy(request_decision, ctx, verdict, store, level):
    """The protected mobile action: layer attestation, signing and verdict on L0."""
    decision = combine([
        (1, "L1", attestation.score(ctx, verdict)),
        (2, "L2", request_signing.score(ctx, verdict, store)),
        (3, "L3", device_verdict.score(ctx, verdict, store)),
    ], level, base=request_decision)
    decision["features"] = {
        "integrity": None if verdict is None else verdict.get("deviceIntegrity"),
        "appIntegrity": None if verdict is None else verdict.get("appIntegrity"),
        "deviceId": None if verdict is None else verdict.get("deviceId"),
        "attested": verdict is not None,
    }
    return decision


if __name__ == '__main__':
    for s in (0, 25, 30, 59, 60, 100):
        print(s, outcome_for(s))
