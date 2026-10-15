"""
The model as one more sensor, in three roles

W2 Ch7 trained a LightGBM classifier and scored checkouts with it. Here it joins the rule stack the
only way a model should join one: as a sensor that *reports* two signals, with weights that live in
policy.py like everyone else's:

    model_suspicious   p >= t_suspicious   (+30 by default: the challenge band)
    model_bot          p >= t_bot          (+60: the block line)

The thresholds belong to the model version (registry.py), because every retrain moves the score
distribution. The weights belong to the policy, because a weight of 0 is the kill switch for a model
that has gone wrong.

Three roles, same request, same feature vector:
    prod     its signals go into the score                        (acts)
    shadow   scored, logged, metered, never in the score          (observes)
    canary   acts instead of prod for canary_pct % of people,     (acts for a few)
             chosen by a stable hash of the account being signed in to, so one person never
             flips between models from one sign-in to the next

Boosters hot-reload when the manifest or a model file changes, so promoting, shadowing and rolling
back are file writes, never restarts. No model holds a role until the operator promotes one, and
until then this check says nothing.
"""

import hashlib
import os

from . import attempt, mlfeatures, netinfo, ops, registry, sensors
from .features import numbers, of
from .pipeline import Check

try:
    import lightgbm as lgb
except ImportError:  # the store still runs rules-only without the ML stack
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


def canary_bucket(key, pct):
    """Stable assignment: the same key always lands on the same side."""
    if not pct or not key:
        return False
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % 100 < pct


def verdict(p, meta):
    if p >= meta["t_bot"]:
        return "bot"
    if p >= meta["t_suspicious"]:
        return "suspicious"
    return "clean"


def _check(ctx):
    """Signals from the acting model; every role's probability and verdict go to the log."""
    if lgb is None:
        return None
    roles, versions = _roles()
    if not any(roles.values()):
        return None
    row = mlfeatures.vector(sensors.flat(ctx), numbers(of(ctx)), netinfo.of(ctx)["kind"])
    info = {}
    for role, version in roles.items():
        if not version:
            continue
        booster = _booster(version)
        if booster is None:
            continue
        p = float(booster.predict([row])[0])
        info[role] = {"version": version, "p": round(p, 4), "verdict": verdict(p, versions[version])}

    pct = ops.state(ctx)["cfg"].get("canary_pct", 0)
    person = attempt.credentials(ctx)[0] or ctx.edge.ip
    acting = "canary" if "canary" in info and canary_bucket(person, pct) else "prod"
    info["acting"] = acting
    ctx.note(model=info)
    v = info.get(acting, {}).get("verdict")
    name = {"bot": "model_bot", "suspicious": "model_suspicious"}.get(v)
    if name is None:
        return None
    return sensors.emit(ctx, LAYER, [name])


CHECK = Check("model", _check, phases=sensors.LOGIN)
