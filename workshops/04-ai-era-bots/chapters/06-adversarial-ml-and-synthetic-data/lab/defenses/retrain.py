"""
W4 Ch6 — Shared deployment helper for the robust/sanitized/augmented models

The three defense scripts (robust_train, provenance, augment) all end the
same way: fit LightGBM on a labelled feature set, pick an operating point
from a false-positive budget on out-of-fold verified-human scores (the W2
Ch7 discipline), and save the native text model + a JSON sidecar scorer.py
can load. They differ only in how they PREPARE the data and whether they
constrain the model. That shared tail lives here.

`deploy()` is infrastructure, not a student exercise. Each defense passes:
  df, label   the feature frame and its weak labels (NaN = unlabeled)
  feats       the feature columns (FEATURE_SETS[2]: per-session + cohort)
  version     2..5, the model_v{version} files to write
  monotone    optional {feature: +1|-1} constraints (robust_train)
  extra_bot   optional extra bot-labelled rows to fold in (adversarial training)
"""

import json
import os
import sys
import time

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import KFold

sys.path.insert(0, os.path.dirname(__file__))

from features import CATEGORICAL  # noqa: E402
from train import (ARTIFACTS, FPR_BUDGET, LGB_PARAMS, MIN_THRESHOLD, NUM_ROUNDS,  # noqa: E402
                   threshold_for_budget)

# Hard tells: signals whose direction is not up for negotiation. Constraining
# the model to be monotone in them means an attacker cannot buy a lower score
# by piling on human-looking features while keeping a tell switched on.
HARD_TELLS = {
    "no_accept_language": 1, "ua_is_library": 1, "webdriver": 1, "software_gpu": 1,
    "ua_platform_mismatch": 1, "gpu_platform_mismatch": 1,
    "touch_platform_mismatch": 1, "tz_ip_mismatch": 1,
    "has_fp": -1, "has_beh": -1,
}


def _monotone_vector(feats, monotone):
    if not monotone:
        return None
    # LightGBM forbids a monotone constraint on a categorical feature.
    return [0 if f in CATEGORICAL else int(monotone.get(f, 0)) for f in feats]


def _fitter(feats, monotone):
    constraints = _monotone_vector(feats, monotone)
    params = dict(LGB_PARAMS)
    if constraints is not None:
        params["monotone_constraints"] = constraints

    def _fit(rows):
        data = lgb.Dataset(rows[feats], rows["label"], categorical_feature=CATEGORICAL)
        return lgb.train(params, data, num_boost_round=NUM_ROUNDS)
    return _fit


def _oof(lab, feats, fit, k=5):
    lab = lab.sort_values("ts")
    oof = np.zeros(len(lab))
    for tr, te in KFold(k, shuffle=False).split(lab):
        oof[te] = fit(lab.iloc[tr]).predict(lab.iloc[te][feats])
    return lab, oof


MODEL = "model"   # the single deployed model scorer.py hot-reloads


def deploy(df, label, feats, stage, monotone=None, extra_bot=None,
           fpr_budget=FPR_BUDGET, note=""):
    """Fit, threshold on an FPR budget, and save model.(txt|json).

    `stage` is a human label ('base', 'robust', 'sanitized', 'augmented') for
    the scorer's /lab/status line. There is ONE model file: each defense
    overwrites it and the running site hot-reloads it, so a round that only
    retrains needs no restart.
    """
    df = df.copy()
    df["label"] = label
    lab = df[df["label"].notna()].copy()
    lab["label"] = lab["label"].astype(int)
    if extra_bot is not None and not extra_bot.empty:
        extra = extra_bot.copy()
        extra["label"] = 1
        lab = pd.concat([lab, extra[[c for c in lab.columns if c in extra.columns]]],
                        ignore_index=True)
    if "ts" not in lab:
        lab["ts"] = np.arange(len(lab))
    lab["ts"] = lab["ts"].fillna(lab["ts"].max())

    fit = _fitter(feats, monotone)
    lab_sorted, oof = _oof(lab, feats, fit)
    humans = oof[lab_sorted["label"].to_numpy() == 0]
    threshold = max(threshold_for_budget(humans, fpr_budget), MIN_THRESHOLD)

    booster = fit(lab)
    valid_mask = lab_sorted["label"].nunique() == 2
    os.makedirs(ARTIFACTS, exist_ok=True)
    booster.save_model(os.path.join(ARTIFACTS, f"{MODEL}.txt"))
    meta = {"stage": stage, "features": feats, "categorical": CATEGORICAL,
            "threshold": threshold, "fpr_budget": fpr_budget,
            "monotone": bool(monotone), "note": note,
            "n_labeled": int(len(lab)),
            "n_bot": int((lab["label"] == 1).sum()),
            "n_human": int((lab["label"] == 0).sum()),
            "trained_at": time.time(),
            "holdout_auc": float(roc_auc_score(lab_sorted["label"], oof)) if valid_mask else None}
    with open(os.path.join(ARTIFACTS, f"{MODEL}.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    return booster, meta
