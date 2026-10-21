"""
The shared tail of every training script in this chapter (infrastructure, not a student exercise)

The baseline (baseline_model.py) and the three defenses (robust_train.py, provenance.py, augment.py) all
end the same way: fit LightGBM on a labelled feature set, pick an operating point from a false-positive
budget on out-of-fold verified-human scores (W2 Ch7's discipline: "block at most 1% of verified
customers" is a business decision, not an F1 optimum), and save LightGBM's native text model plus a JSON
sidecar that ml_check.py loads. They differ only in how they PREPARE the data and whether they CONSTRAIN
the model. That shared tail lives here.

`deploy()` takes
  df, label   the feature frame (features.build_dataset) and its weak labels (NaN = unlabeled)
  feats       the feature columns (features.FEATURE_SETS[2]: per-session + cohort)
  version     2..5, the artifacts/model_v<version>.* files to write (models.py)
  monotone    optional {feature: +1|-1} constraints (robust_train)
  extra_bot   optional extra rows to fold in as confirmed bots (adversarial examples, synthetic rows)

Each stage writes its OWN file, so the level N-1 model is still there for the "before" column.
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

from . import models
from .features import CATEGORICAL, FEATURE_SETS

# The same recipe as W2 Ch7's model (defenses/train.py there): a small, shallow, deterministic LightGBM.
LGB_PARAMS = {
    "objective": "binary", "learning_rate": 0.05, "num_leaves": 15,
    "min_data_in_leaf": 5, "feature_fraction": 0.9, "is_unbalance": True,
    "seed": 7, "deterministic": True, "num_threads": 1, "verbose": -1,
}
NUM_ROUNDS = 150
FPR_BUDGET = 0.01       # the share of verified customers you accept blocking
# When labeled humans and bots are perfectly separable, the budget quantile of human scores lands
# near 0 and would block anything slightly unusual. Never go below this floor.
MIN_THRESHOLD = 0.5

FEATURES = list(FEATURE_SETS[2])      # per-session + cohort features: W2 Ch7's v2 feature set

# Hard tells: signals whose direction is not up for negotiation. Constraining the model to be monotone
# in them means an attacker cannot buy a lower score by piling on human-looking features while a tell
# stays switched on.
HARD_TELLS = {
    "no_accept_language": 1, "ua_is_library": 1, "webdriver": 1, "software_gpu": 1,
    "ua_platform_mismatch": 1, "gpu_platform_mismatch": 1,
    "touch_platform_mismatch": 1, "tz_ip_mismatch": 1,
    "has_fp": -1, "has_beh": -1,
}


def threshold_for_budget(human_scores, budget):
    """Smallest threshold that blocks at most `budget` of these humans."""
    if len(human_scores) == 0:
        return 0.5
    t = float(np.quantile(human_scores, 1 - budget, method="higher"))
    return min(t + 1e-6, 0.999999)


def _monotone_vector(feats, monotone):
    if not monotone:
        return None
    # LightGBM forbids a monotone constraint on a categorical feature.
    return [0 if f in CATEGORICAL else int(monotone.get(f, 0)) for f in feats]


def _fitter(feats, monotone):
    params = dict(LGB_PARAMS)
    constraints = _monotone_vector(feats, monotone)
    if constraints is not None:
        params["monotone_constraints"] = constraints

    def _fit(rows):
        data = lgb.Dataset(rows[feats], rows["label"], categorical_feature=CATEGORICAL)
        return lgb.train(params, data, num_boost_round=NUM_ROUNDS)
    return _fit


def _oof(lab, feats, fit, k=5):
    """Score every labeled row with a model trained on the other folds (time-ordered blocks)."""
    lab = lab.sort_values("ts")
    oof = np.zeros(len(lab))
    for tr, te in KFold(k, shuffle=False).split(lab):
        oof[te] = fit(lab.iloc[tr]).predict(lab.iloc[te][feats])
    return lab, oof


def labeled(df, label, extra_bot=None):
    """The labelled training rows: the weak labels, plus `extra_bot` rows folded in as confirmed bots."""
    df = df.copy()
    df["label"] = label
    lab = df[df["label"].notna()].copy()
    lab["label"] = lab["label"].astype(int)
    if extra_bot is not None and not extra_bot.empty:
        extra = extra_bot.copy()
        extra["label"] = 1
        lab = pd.concat([lab, extra[[c for c in lab.columns if c in extra.columns]]], ignore_index=True)
    if "ts" not in lab:
        lab["ts"] = np.arange(len(lab))
    lab["ts"] = lab["ts"].fillna(lab["ts"].max())
    return lab


def deploy(df, label, feats, version, stage, monotone=None, extra_bot=None, fpr_budget=FPR_BUDGET, note=""):
    """Fit, threshold on an FPR budget, and save artifacts/model_v<version>.(txt|json). Returns (booster, meta)."""
    lab = labeled(df, label, extra_bot)
    if lab["label"].nunique() < 2:
        sys.exit("The labelled set has only one class: nothing to train on. Run tools/simulate.py first.")
    fit = _fitter(feats, monotone)
    lab_sorted, oof = _oof(lab, feats, fit)
    humans = oof[lab_sorted["label"].to_numpy() == 0]
    threshold = max(threshold_for_budget(humans, fpr_budget), MIN_THRESHOLD)
    booster = fit(lab)
    os.makedirs(models.ARTIFACTS, exist_ok=True)
    name = f"model_v{version}"
    booster.save_model(models.path(f"{name}.txt"))
    meta = {"version": version, "stage": stage, "features": feats, "categorical": CATEGORICAL,
            "threshold": threshold, "fpr_budget": fpr_budget, "monotone": bool(monotone), "note": note,
            "n_labeled": int(len(lab)), "n_bot": int((lab["label"] == 1).sum()),
            "n_human": int((lab["label"] == 0).sum()), "trained_at": time.time(),
            "holdout_auc": float(roc_auc_score(lab_sorted["label"], oof))}
    with open(models.path(f"{name}.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    return booster, meta


def report(title, meta):
    print(f"=== {title}: {meta['n_bot']} bot / {meta['n_human']} human labelled, "
          f"threshold {meta['threshold']:.3f}, out-of-fold AUC {meta['holdout_auc']:.3f} ===")
    print(f"  saved artifacts/model_v{meta['version']}.txt + .json (the store reloads it on the next purchase)")
