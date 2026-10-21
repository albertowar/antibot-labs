"""
The deployed scoring check: what the store runs at every purchase attempt (levels 1 to 4)

This is the asset the attacker spends the chapter trying to steal, evade, poison and slip past. It is
infrastructure, not a student exercise: a W2 Ch7 style model scoring the session, plus the human-only
anomaly detector, behind the oracle guard (oracle_guard.py).

    DEFENSE_LEVEL=1   model v2: the deployed baseline
    DEFENSE_LEVEL=2   model v3: adversarial training + monotone constraints   (Round 2)
    DEFENSE_LEVEL=3   model v4: provenance-sanitized training set            (Round 3)
    DEFENSE_LEVEL=4   model v5: SMOTE for the rare class                     (Round 4)

The wiring never changes, the model does: `models.version(level)` picks the file, and a defense script
writes it. `risk` is normalised so that 1.0 is the blocking line at every level:

    risk = max(p_bot / t_bot, anomaly / t_anomaly)

The check turns it into points on the engine's 0 to 100 scale (points() below), so risk 1.0 lands exactly
on policy.BANDS["block"] (75) and the purchase is refused BEFORE the order is written. Nothing is held,
nothing is cancelled later: the answer is a 200 or a 403, and that single bit is what Round 1's
extraction attack reads, one probe at a time.

It runs inline on the purchase request, on the customer's time. Features are a few Redis reads plus plain
Python; inference on one row is far below a millisecond. The checkpoint reports the check's own time
(`ml_ms` in the decision log) as the defender's cost.

A level whose model is not trained yet FAILS OPEN and says so in the decision log (`ml_error`): the
checkpoint refuses to run until you train it (python -m defenses.baseline_model, or --catch-up).
"""

import time

import numpy as np

from demo_site.ext import ml_store

from . import anomaly, cohort, features, models
from .pipeline import Check, Signal

POINTS_PER_RISK = 75        # policy.BANDS["block"]: risk 1.0 is the blocking line


def points(risk):
    """
    Risk on the engine's 0 to 100 scale: 75 points per unit up to the blocking line, then a smooth climb
    towards 100 (risk 2 is 87, risk 4 is 93). A hard cap at 100 would flatten everything above risk 1.33
    into one number; this keeps the score strictly increasing.
    """
    if risk < 1.0:
        return int(POINTS_PER_RISK * risk)
    return int(POINTS_PER_RISK + (100 - POINTS_PER_RISK) * (1 - 1 / risk))


def combine(p_bot, t_bot, anomaly_score, t_anomaly):
    """
    Normalised risk: >= 1.0 means block. The session is blocked on EITHER signal: the supervised model
    knows the bots it was trained on, the anomaly detector flags devices no verified human has. The price of
    "either" is that the anomaly detector's false positives (privacy browsers, Linux desktops, new phones)
    are blocked too. Requiring both would lose the families only the anomaly detector sees.
    """
    risk = p_bot / t_bot
    if anomaly_score is not None:
        risk = max(risk, anomaly_score / t_anomaly)
    return risk


def session_features(ctx, meta):
    """This session's features as of now: the SAME features.compute() the training set used."""
    events, telemetry, email = ml_store.session_rows(ctx.redis, ctx.session.sid)
    as_of = ctx.attrs.get("ml_ts", time.time())
    window = None
    if any(name in cohort.COHORT_FEATURES for name in meta["features"]):
        first = min(events, key=lambda r: r["ts"]) if events else {}
        fps = sorted((t for t in telemetry if t["kind"] == "fp" and t["ts"] <= as_of), key=lambda t: t["ts"])
        window = cohort.window_from_redis(ctx.redis, as_of, first.get("ip", ""), fps[-1]["fp_hash"] if fps else None)
    return features.compute(events, telemetry, email, as_of, window)


def score(ctx):
    """(risk, p_bot, anomaly) for the session at this purchase, with the model of the current level."""
    booster, meta = models.load_model(models.version(ctx.level))
    f = session_features(ctx, meta)
    x = np.array([[f.get(name, np.nan) for name in meta["features"]]], dtype=float)
    # One row: a single thread beats spinning up an OpenMP pool per request
    p_bot = float(booster.predict(x, num_threads=1)[0])
    detector = anomaly.AnomalyModel(models.load_anomaly_meta())
    a_score = detector.score_row(f)
    return combine(p_bot, meta["threshold"], a_score, detector.threshold), p_bot, a_score


def _check(ctx):
    if models.missing(ctx.level):
        ctx.note(ml_error="not trained: " + ", ".join(models.missing(ctx.level)))
        return None
    t0 = time.perf_counter()
    risk, p_bot, a_score = score(ctx)
    ctx.note(ml_p=round(p_bot, 4), ml_anomaly=round(a_score, 3), ml_risk=round(risk, 3),
             ml_ms=round((time.perf_counter() - t0) * 1000, 2))
    return [Signal("ml", "risk", points(risk), f"p={p_bot:.2f}")]


CHECK = Check("ml", _check, phases=("action:drop_buy",))
