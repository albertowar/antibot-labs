"""
W2 Ch1 — Sensor Scoring Engine (Section 1.5)

Adds up the points from every layer enabled by DEFENSE_LEVEL, the same
additive model as Workshop 1, Chapter 4, so you can read every verdict as a
list of reasons.

    Level 0  sensor collected and logged, nothing enforced (edge rules only)
    Level 1  + sensor gate, automation artifacts    (automation_artifacts.py)
    Level 2  + consistency                          (consistency.py)
    Level 3  + lie detection                        (lie_detection.py)
    Level 4  + interaction evidence on the cart     (interaction.py)

Thresholds:
    score >= 40  bot         (403)
    score >= 20  suspicious  (logged, allowed through)
    score <  20  clean

Why additive points and not a probability? Because at this stage you have
no labelled data to calibrate a probability against, and a list of reasons
is what you need to debug false positives. Workshop 2, Chapter 7 replaces
the hand-set weights with a model trained on exactly these signals.
"""

from automation_artifacts import score_automation_artifacts
from consistency import score_consistency
from interaction import score_interaction
from lie_detection import score_lies

BOT_THRESHOLD = 40
SUSPICIOUS_THRESHOLD = 20


def get_verdict(score):
    if score >= BOT_THRESHOLD:
        return "bot"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


def evaluate_sensor(signals, headers, level):
    """
    Score one sensor payload with every layer up to `level`.

    signals  the JSON the sensor posted (see demo_site/static/sensor.js)
    headers  the headers of that POST, for the JS-vs-HTTP checks

    Returns (score, reasons, verdict). Each reason is tagged with its layer.
    """
    layers = [
        (1, "L1", lambda: score_automation_artifacts(signals)),
        (2, "L2", lambda: score_consistency(signals, headers)),
        (3, "L3", lambda: score_lies(signals)),
    ]
    score = 0
    reasons = []
    for min_level, tag, check in layers:
        if level < min_level:
            continue
        points, why = check()
        score += points
        reasons.extend(f"[{tag}] {r}" for r in why)
    return score, reasons, get_verdict(score)


def evaluate_action(sensor_score, sensor_reasons, interaction, signals, level):
    """
    Score an action (Add to cart): the session's sensor score plus, from
    Level 4, the evidence of how the click happened.
    Returns (score, reasons, verdict).
    """
    score, reasons = sensor_score, list(sensor_reasons)
    if level >= 4:
        points, why = score_interaction(interaction, signals)
        score += points
        reasons.extend(f"[L4] {r}" for r in why)
    return score, reasons, get_verdict(score)
