"""
Chapter 7 — Online scoring: what the demo site runs at every checkout

    DEFENSE_LEVEL=0   log only, no model
    DEFENSE_LEVEL=1   model v1 (per-session features)
    DEFENSE_LEVEL=2   model v2 (+ cohort features)
    DEFENSE_LEVEL=3   model v2 + anomaly detector
    DEFENSE_LEVEL=4   level 3, with deferred enforcement (enforcement.py)

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
MODEL_FOR_LEVEL = {1: 1, 2: 2, 3: 2, 4: 2}


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
        self.version = MODEL_FOR_LEVEL.get(level)
        self._mtime = None
        self.booster = self.meta = self.anomaly = None
        if self.version:
            self.reload()

    def _paths(self):
        paths = [os.path.join(ARTIFACTS, f"model_v{self.version}.txt")]
        if self.level >= 3:
            paths.append(os.path.join(ARTIFACTS, "anomaly_v3.json"))
        return paths

    def missing(self):
        return [os.path.relpath(p, os.path.join(ARTIFACTS, "..")) for p in self._paths()
                if not os.path.exists(p)]

    def reload(self):
        if self.missing():
            return
        mtime = max(os.path.getmtime(p) for p in self._paths())
        if mtime == self._mtime:
            return
        base = os.path.join(ARTIFACTS, f"model_v{self.version}")
        self.booster = lgb.Booster(model_file=f"{base}.txt")
        with open(f"{base}.json") as fh:
            self.meta = json.load(fh)
        self.anomaly = AnomalyModel.load() if self.level >= 3 else None
        self._mtime = mtime

    def describe(self):
        if not self.version:
            return {"model": None}
        if self.missing():
            return {"model": f"v{self.version}", "missing": self.missing()}
        d = {"model": f"v{self.version}", "threshold": round(self.meta["threshold"], 4),
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
