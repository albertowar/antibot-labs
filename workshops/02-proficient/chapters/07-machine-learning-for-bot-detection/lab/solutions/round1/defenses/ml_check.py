"""
The scoring check: what the store runs at every purchase attempt (Rounds 1 to 4)

One check serves every round, because the model is what changes, not the wiring:

    DEFENSE_LEVEL=1   model v1 (per-session features)
    DEFENSE_LEVEL=2   model v2 (+ cohort features)
    DEFENSE_LEVEL=3   model v2 + the anomaly detector, risk = max(p / t, a / t_a)
    DEFENSE_LEVEL=4   the same score, but never a verdict: deferred enforcement (enforcement.py)

`risk` is normalised so that 1.0 is the blocking line at every level. The check turns it into
points on the engine's 0 to 100 scale (points() below), so risk 1.0 lands exactly on
policy.BANDS["block"] (75) and the gate's `X-Lab-Score` is a monotonic function of the risk. That header is a
teaching aid and a deliberate mistake: Round 3 exploits it and Round 4 removes the oracle.

It runs inline on the purchase request, on the customer's time. Features are a few Redis reads plus
plain Python; inference on one row is far below a millisecond. The checkpoint reports the check's
own time (`ml_ms` in the decision log) next to the gate's `Server-Timing`.

The model hot-reloads when its file changes, so retraining needs no restart. A level whose model is
not trained yet FAILS OPEN and says so in the decision log (`ml_error`): the checkpoint refuses to
run until you train it.
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
    into one number; this keeps the score strictly increasing, which is the gradient Round 3 follows
    and Round 4 closes.
    """
    if risk < 1.0:
        return int(POINTS_PER_RISK * risk)
    return int(POINTS_PER_RISK + (100 - POINTS_PER_RISK) * (1 - 1 / risk))


def combine(p_bot, t_bot, anomaly_score, t_anomaly):
    """
    Normalised risk: >= 1.0 means block.

    EXERCISE (Round 3): this blocks on EITHER signal. Look at who the anomaly detector flags in
    `python tools/audit.py anomaly`. Try requiring some supervised suspicion too, e.g. block on
    anomaly only when p_bot >= 0.3 * t_bot, and re-run the checkpoint. Which bots get through, and
    which humans stop being blocked?
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


def _check(ctx):
    level = ctx.level
    if models.missing(level):
        ctx.note(ml_error="not trained: " + ", ".join(models.missing(level)))
        return None
    t0 = time.perf_counter()
    booster, meta = models.load_model(models.MODEL_FOR_LEVEL[min(level, 4)])
    f = session_features(ctx, meta)
    x = np.array([[f.get(name, np.nan) for name in meta["features"]]], dtype=float)
    # One row: a single thread beats spinning up an OpenMP pool per request
    p_bot = float(booster.predict(x, num_threads=1)[0])
    a_score = a_threshold = None
    if level >= 3:
        detector = anomaly.AnomalyModel(models.load_anomaly_meta())
        a_score, a_threshold = detector.score_row(f), detector.threshold
    risk = combine(p_bot, meta["threshold"], a_score, a_threshold)
    ctx.note(ml_p=round(p_bot, 4), ml_anomaly=None if a_score is None else round(a_score, 3),
             ml_risk=round(risk, 3), ml_ms=round((time.perf_counter() - t0) * 1000, 2))
    if level >= 4:
        ctx.attrs["ml_deferred"] = {"risk": risk}     # demo_site/ext/ml.py answers 202 and enforcement.py decides later
        return None
    return [Signal("ml", "risk", points(risk), f"p={p_bot:.2f}")]


CHECK = Check("ml", _check, phases=("action:drop_buy",))
