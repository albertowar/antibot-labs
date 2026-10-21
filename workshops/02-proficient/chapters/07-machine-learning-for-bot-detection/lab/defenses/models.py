"""
Model artifacts: where they live, what each defense level needs, and how the store loads them.

    artifacts/model_v1.txt + .json    LightGBM text model + sidecar (features, threshold, budget)  (Round 1)
    artifacts/model_v2.txt + .json    the same with cohort features                                 (Round 2)
    artifacts/anomaly_v3.json         device-claim likelihood tables + threshold                    (Round 3)
    artifacts/reference_features.parquet  the training-time feature distribution W3 Ch10 monitors

LightGBM's native text format, never pickle: a pickled model executes code when it is loaded, so a
model file becomes a supply-chain target (W3 Ch8). Models reload when their files change, so
retraining needs no restart.
"""

import json
import os

import lightgbm as lgb

ARTIFACTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "artifacts")
MODEL_FOR_LEVEL = {1: 1, 2: 2, 3: 2, 4: 2}
_cache = {}


def time_scale():
    from .features import LAB_TIME_SCALE
    return LAB_TIME_SCALE


def path(name):
    return os.path.join(ARTIFACTS, name)


def needed(level):
    """The artifact files DEFENSE_LEVEL `level` cannot run without."""
    if level < 1:
        return []
    files = [f"model_v{MODEL_FOR_LEVEL[min(level, 4)]}.txt", f"model_v{MODEL_FOR_LEVEL[min(level, 4)]}.json"]
    return files + (["anomaly_v3.json"] if level >= 3 else [])


def missing(level):
    return [f"artifacts/{n}" for n in needed(level) if not os.path.exists(path(n))]


def _cached(key, files, build):
    mtime = max(os.path.getmtime(path(f)) for f in files)
    hit = _cache.get(key)
    if hit is None or hit[0] != mtime:
        hit = _cache[key] = (mtime, build())
    return hit[1]


def load_model(version):
    """(Booster, meta) for model v<version>. Raises FileNotFoundError when it is not trained."""
    files = [f"model_v{version}.txt", f"model_v{version}.json"]

    def build():
        with open(path(files[1])) as fh:
            return lgb.Booster(model_file=path(files[0])), json.load(fh)
    return _cached(f"model{version}", files, build)


def load_anomaly_meta():
    def build():
        with open(path("anomaly_v3.json")) as fh:
            return json.load(fh)
    return _cached("anomaly", ["anomaly_v3.json"], build)


def describe(level):
    """What a store at this level is scoring with (GET /lab/ml/status)."""
    if level < 1:
        return {"model": None}
    if missing(level):
        return {"model": f"v{MODEL_FOR_LEVEL[min(level, 4)]}", "missing": missing(level)}
    _, meta = load_model(MODEL_FOR_LEVEL[min(level, 4)])
    d = {"model": f"v{meta['version']}", "threshold": round(meta["threshold"], 4), "fpr_budget": meta["fpr_budget"]}
    if level >= 3:
        d["anomaly_threshold"] = round(load_anomaly_meta()["threshold"], 4)
    return d
