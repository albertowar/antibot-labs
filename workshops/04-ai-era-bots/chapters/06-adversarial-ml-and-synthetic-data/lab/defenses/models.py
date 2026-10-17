"""
Model artifacts: where they live, which one each defense level scores with, and how the store loads them.

    artifacts/model_v2.txt + .json    the deployed baseline: W2 Ch7's model, retrained here    (level 1)
    artifacts/model_v3.txt + .json    + adversarial examples and monotone constraints          (level 2, Round 2)
    artifacts/model_v4.txt + .json    + provenance sanitization of the training set            (level 3, Round 3)
    artifacts/model_v5.txt + .json    + SMOTE for the rare class                               (level 4, Round 4)
    artifacts/anomaly_v3.json         the human-only device-claim detector (W2 Ch7 Round 3), part of
                                      the deployed stack at every level

The version numbers continue W2 Ch7's (v1, v2 were its models): v2 is the model you inherit, and each
round of this chapter ships the next one. Level L scores with model v(L+1), so `--level N-1` runs a
round's attackers against the PREVIOUS round's model. LightGBM's native text format, never pickle: a
pickled model executes code when it is loaded, so a model file is a supply-chain target.
Models reload when their files change, so retraining needs no restart.
"""

import json
import os

import lightgbm as lgb

ARTIFACTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "artifacts")
VERSION_FOR_LEVEL = {1: 2, 2: 3, 3: 4, 4: 5}
STAGE_FOR_VERSION = {2: "base", 3: "robust", 4: "sanitized", 5: "augmented"}
_cache = {}


def time_scale():
    from .features import LAB_TIME_SCALE
    return LAB_TIME_SCALE


def path(name):
    return os.path.join(ARTIFACTS, name)


def version(level):
    return VERSION_FOR_LEVEL[min(max(level, 1), 4)]


def needed(level):
    """The artifact files DEFENSE_LEVEL `level` cannot run without."""
    if level < 1:
        return []
    v = version(level)
    return [f"model_v{v}.txt", f"model_v{v}.json", "anomaly_v3.json"]


def missing(level):
    return [f"artifacts/{n}" for n in needed(level) if not os.path.exists(path(n))]


def _cached(key, files, build):
    mtime = max(os.path.getmtime(path(f)) for f in files)
    hit = _cache.get(key)
    if hit is None or hit[0] != mtime:
        hit = _cache[key] = (mtime, build())
    return hit[1]


def load_model(v):
    """(Booster, meta) for model v<v>. Raises FileNotFoundError when it is not trained."""
    files = [f"model_v{v}.txt", f"model_v{v}.json"]

    def build():
        with open(path(files[1])) as fh:
            return lgb.Booster(model_file=path(files[0])), json.load(fh)
    return _cached(f"model{v}", files, build)


def load_anomaly_meta():
    def build():
        with open(path("anomaly_v3.json")) as fh:
            return json.load(fh)
    return _cached("anomaly", ["anomaly_v3.json"], build)


def describe(level):
    """What a store at this level is scoring with (GET /lab/ml/status)."""
    if level < 1:
        return {"model": None}
    v = version(level)
    if missing(level):
        return {"model": f"v{v}", "missing": missing(level)}
    _, meta = load_model(v)
    return {"model": f"v{v}", "stage": meta.get("stage"), "threshold": round(meta["threshold"], 4),
            "fpr_budget": meta["fpr_budget"], "anomaly_threshold": round(load_anomaly_meta()["threshold"], 4)}
