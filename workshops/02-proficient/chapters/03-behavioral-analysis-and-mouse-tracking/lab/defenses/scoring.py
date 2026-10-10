"""
Chapter 3: behavioral scoring engine.

Adds up the points from every layer enabled by DEFENSE_LEVEL:

    Level 0  no defense (score and log only)
    Level 1  + presence & sanity           (l1_presence.py)
    Level 2  + kinematics & keystrokes     (l2_kinematics.py)
    Level 3  + motor-control realism       (l3_motor.py)
    Level 4  + layout jitter & replay      (l4_replay.py)

Verdicts:
    score >= 60  block      (403)
    score >= 30  challenge  (202: step up to a CAPTCHA or PoW, W1 Ch6/Ch7)
    score <  30  allow      (200)

Why three outcomes: behavior is probabilistic. A challenge costs a real
user a few seconds; a block costs them the purchase. Only stack enough
independent evidence to reach "block".
"""

from l1_presence import score_presence
from l2_kinematics import score_kinematics
from l3_motor import score_motor
from l4_replay import score_replay

BLOCK = 60
CHALLENGE = 30


def verdict_for(score):
    if score >= BLOCK:
        return "block"
    if score >= CHALLENGE:
        return "challenge"
    return "allow"


def evaluate(telemetry, features, layout, level, store=None, sid=""):
    """
    Score one session. Returns (score, reasons, verdict, signature).
    Every layer runs (so the logs show what *would* fire), but only the
    enabled ones count. The caller stores `signature` for Layer 4.
    """
    layers = [(1, score_presence(features)), (2, score_kinematics(features)),
              (3, score_motor(features))]
    if level >= 4:
        layers.append((4, score_replay(features, store, sid)))
    score, reasons = 0, []
    for layer, hits in layers:
        for points, reason in hits:
            if layer <= level:
                score += points
                reasons.append(f"[L{layer}] {reason}")
    return score, reasons, verdict_for(score), features["signature"]


def score_offline(trace, level):
    """Score a saved trace without a server (tools/score_trace.py, checkpoint)."""
    from features import extract
    feats = extract(trace["telemetry"], trace["layout"])
    score, reasons, verdict, _ = evaluate(trace["telemetry"], feats, trace["layout"], min(level, 3))
    return score, reasons, verdict
