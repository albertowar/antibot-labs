"""
Chapter 7 — Online scoring: what the demo site runs at every checkout

    DEFENSE_LEVEL=0   log only, no model
    DEFENSE_LEVEL=1   deployed model v2 + anomaly (the chapter's starting state)
    DEFENSE_LEVEL=2   robust model v3 (adversarial training + monotone constraints)
    DEFENSE_LEVEL=3   provenance-sanitized model v4
    DEFENSE_LEVEL=4   SMOTE-augmented model v5

The oracle guard (defenses/oracle_guard.py) wraps the verdict at every
level >= 1; the anomaly detector is part of the deployed stack throughout.

`risk` is normalised so that 1.0 is the blocking line for every level:
    risk = max(p_bot / t_bot, anomaly / t_anomaly)

Latency matters: everything here runs inline on the checkout request.
Feature extraction is a handful of indexed queries plus pandas. Model
inference on one row is far below a millisecond. The checkpoint reports
p50/p95 from the `Server-Timing: mlscore` header.

Models hot-reload when their files change, so retraining does not need a
restart. Changing DEFENSE_LEVEL does.
"""

import json
import os
import sys
import time

import lightgbm as lgb
import numpy as np
from sqlalchemy import text

sys.path.insert(0, os.path.dirname(__file__))

import cohort  # noqa: E402
from anomaly import AnomalyModel  # noqa: E402
from features import compute  # noqa: E402

ARTIFACTS = os.path.join(os.path.dirname(__file__), "..", "artifacts")
MODEL_BASENAME = "model"   # single, hot-reloaded deployed model


def combine(p_bot, t_bot, anomaly, t_anomaly):
    """
    Normalised risk: >= 1.0 means block.

    TODO (Round 3): this blocks on EITHER signal. Look at who the anomaly
    detector flags in `python defenses/anomaly.py --audit`. Try requiring
    some supervised suspicion too, e.g. block on anomaly only when
    p_bot >= 0.3 * t_bot, and re-run the checkpoint. Which bots get
    through, and which humans stop being blocked?
    """
    risk = p_bot / t_bot
    if anomaly is not None:
        risk = max(risk, anomaly / t_anomaly)
    return risk


class Scorer:
    def __init__(self, level):
        self.level = level
        self.active = level >= 1          # level 0 is log-only
        self._mtime = None
        self.booster = self.meta = self.anomaly = None
        if self.active:
            self.reload()

    def _paths(self):
        if not self.active:
            return []
        return [os.path.join(ARTIFACTS, f"{MODEL_BASENAME}.txt"),
                os.path.join(ARTIFACTS, "anomaly_v3.json")]

    def missing(self):
        return [os.path.relpath(p, os.path.join(ARTIFACTS, "..")) for p in self._paths()
                if not os.path.exists(p)]

    def reload(self):
        if self.missing():
            return
        mtime = max(os.path.getmtime(p) for p in self._paths())
        if mtime == self._mtime:
            return
        base = os.path.join(ARTIFACTS, MODEL_BASENAME)
        self.booster = lgb.Booster(model_file=f"{base}.txt")
        with open(f"{base}.json") as fh:
            self.meta = json.load(fh)
        self.anomaly = AnomalyModel.load()
        self._mtime = mtime

    def describe(self):
        if not self.active:
            return {"model": None}
        if self.missing():
            return {"model": "deployed", "missing": self.missing()}
        d = {"model": self.meta.get("stage", "deployed"),
             "threshold": round(self.meta["threshold"], 4),
             "fpr_budget": self.meta["fpr_budget"]}
        if self.anomaly:
            d["anomaly_threshold"] = round(self.anomaly.threshold, 4)
        return d

    def score(self, conn, sid, as_of):
        """Return {risk, p_bot, anomaly} for one session, as of now."""
        self.reload()
        req = [dict(r) for r in conn.execute(
            text("SELECT * FROM requests WHERE sid = :sid"), {"sid": sid}).mappings()]
        tel = [dict(r) for r in conn.execute(
            text("SELECT * FROM telemetry WHERE sid = :sid"), {"sid": sid}).mappings()]
        logins = conn.execute(text("SELECT COUNT(*) FROM logins WHERE sid = :sid"),
                              {"sid": sid}).scalar()
        window = None
        if any(f in cohort.COHORT_FEATURES for f in self.meta["features"]):
            fps = [t["fp_hash"] for t in sorted(tel, key=lambda t: t["ts"])
                   if t["kind"] == "fp" and t["ts"] <= as_of]
            ip = min(req, key=lambda r: r["ts"])["ip"] if req else ""
            window = cohort.window_from_db(conn, as_of, ip, fps[-1] if fps else None)
        f = compute(req, tel, logins, as_of, window)
        x = np.array([[f.get(name, np.nan) for name in self.meta["features"]]], dtype=float)
        # One row: a single thread beats spinning up an OpenMP pool per request
        p_bot = float(self.booster.predict(x, num_threads=1)[0])
        anomaly = self.anomaly.score_row(f) if self.anomaly else None
        risk = combine(p_bot, self.meta["threshold"], anomaly,
                       self.anomaly.threshold if self.anomaly else None)
        return {"risk": risk, "p_bot": p_bot, "anomaly": anomaly}


if __name__ == "__main__":
    from store import make_engine
    level = int(os.environ.get("DEFENSE_LEVEL", "3"))
    s = Scorer(level)
    print(f"level {level}: {s.describe()}")
    if len(sys.argv) > 1 and not s.missing():
        with make_engine().connect() as conn:
            print(s.score(conn, sys.argv[1], time.time()))
