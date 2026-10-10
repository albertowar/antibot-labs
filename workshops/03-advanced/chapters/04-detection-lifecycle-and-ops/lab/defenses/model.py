"""
Chapter 4 (W3): The model as one more sensor, in three roles

W2 Ch7 trained a LightGBM classifier and scored checkouts with it. Here it
joins the W2 Ch8 pipeline the only way a model should join a rule stack: as
a sensor that *reports* two signals, with weights that live in policy.py like
everyone else's:

    model_suspicious   p >= t_suspicious   (+30 by default: the challenge band)
    model_bot          p >= t_bot          (+60: the block line)

The thresholds belong to the model version (registry.py), because every
retrain moves the score distribution. The weights belong to the policy,
because a weight of 0 is the kill switch for a model that has gone wrong.

Three roles, same request, same feature vector:
    prod     its signals go into the score                        (acts)
    shadow   scored, logged, metered, never in the score          (observes)
    canary   acts instead of prod for canary_pct % of sessions,   (acts for a few)
             chosen by a stable hash of the session id so one
             person never flips between models mid-session

Boosters hot-reload when the manifest or a model file changes, so promoting,
shadowing and rolling back are file writes, never restarts.
"""

import os

import config
import features
import registry

try:
    import lightgbm as lgb
except ImportError:  # the app still runs rules-only without the ML stack
    lgb = None

SIGNALS = {
    "model_suspicious": "the production model's probability is above its challenge threshold",
    "model_bot": "the production model's probability is above its block threshold",
}
LAYER = "model"

_boosters = {}   # version -> (mtime, booster)
_manifest = {"mtime": None, "data": None}


def _roles():
    try:
        mtime = os.path.getmtime(registry.MANIFEST)
    except OSError:
        return {}, {}
    if mtime != _manifest["mtime"]:
        _manifest.update(mtime=mtime, data=registry.load())
    data = _manifest["data"]
    return data["roles"], data["versions"]


def _booster(version):
    path = registry.model_path(version)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    cached = _boosters.get(version)
    if cached is None or cached[0] != mtime:
        _boosters[version] = (mtime, lgb.Booster(model_file=path))
    return _boosters[version][1]


def canary_bucket(sid, pct):
    """Stable assignment: the same session always lands on the same side."""
    if not pct:
        return False
    try:
        return int(sid[-4:], 16) % 100 < pct
    except ValueError:
        return False


def verdict(p, meta):
    if p >= meta["t_bot"]:
        return "bot"
    if p >= meta["t_suspicious"]:
        return "suspicious"
    return "clean"


def sense(ctx, flat_signals):
    """Returns (signals_from_the_acting_model, info). info holds every role's
    probability and verdict for the log, the metrics and the shadow report."""
    if lgb is None:
        return [], {}
    roles, versions = _roles()
    if not any(roles.values()):
        return [], {}
    row = features.vector(flat_signals, features.telemetry_numbers(ctx.telemetry),
                          ctx.edge.get("type", "unknown"))
    info = {}
    for role, version in roles.items():
        if not version:
            continue
        booster = _booster(version)
        if booster is None:
            continue
        p = float(booster.predict([row])[0])
        info[role] = {"version": version, "p": round(p, 4), "verdict": verdict(p, versions[version])}

    pct = config.load().get("canary_pct", 0)
    acting = "canary" if "canary" in info and canary_bucket(ctx.sid, pct) else "prod"
    info["acting"] = acting
    v = info.get(acting, {}).get("verdict")
    if v == "bot":
        return ["model_bot"], info
    if v == "suspicious":
        return ["model_suspicious"], info
    return [], info
