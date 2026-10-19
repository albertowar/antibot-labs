"""
Train the session model (Rounds 1 and 2)

    python -m defenses.train --round 1            # v1: per-session features
    python -m defenses.train --round 2            # v2: + cohort features + manual labels
    python -m defenses.train --round 1 --include-leaky   # see what leakage looks like
    python -m defenses.train --round 1 --random-split    # see what a random split hides

What it does
  1. Builds one row per purchase attempt (features.build_dataset) and attaches weak labels
     (labels.py). Writes artifacts/reference_features.parquet: the training-time feature
     distribution W3 Ch8 monitors for drift.
  2. EVALUATES on a split by TIME: the oldest 70% train, the newest 30% are the holdout. Bots
     arrive in campaigns, and a random split puts sessions from the same campaign on both sides,
     so it grades the model on sessions it has effectively already seen. A logistic-regression
     baseline is trained next to LightGBM: never ship a model that cannot beat the simple one.
  3. DEPLOYS a model refit on all labels (so the newest campaign is learned) and picks its
     operating point from a false-positive BUDGET on out-of-fold verified-human scores, not from
     0.5 and not from F1. "Block at most 1% of verified customers" is a business decision. Write
     it down and own it.
  4. Saves LightGBM's native text model + a JSON sidecar. No pickle: a pickled model file executes
     code when loaded, so a model artifact becomes a supply-chain target (W3 Ch7).

Caveat on the false-positive estimate: validation humans are loyal, signed-in customers. Users
who never sign in (privacy browsers, VPNs) are not in it. The checkpoint measures the real
number on every simulated cohort.

The training set is data/history/ and nothing else (defenses/history.py).
"""

import argparse
import json
import os
import sys
import time

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import KFold, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from . import history, models
from .features import CATEGORICAL, FEATURE_SETS, LEAKY_FEATURES, build_dataset
from .labels import weak_labels

ARTIFACTS = models.ARTIFACTS

# EXERCISE (Round 1): the share of verified customers you accept blocking.
# Try 0.002 and 0.05 and compare bot recall in the operating-points table.
FPR_BUDGET = 0.01
# When labeled humans and bots are perfectly separable, the budget quantile of
# human scores lands near 0 and would block anything slightly unusual. Never
# go below this floor: it is a guard against easy labels, not a tuning knob.
MIN_THRESHOLD = 0.5

LGB_PARAMS = {
    "objective": "binary", "learning_rate": 0.05, "num_leaves": 15,
    "min_data_in_leaf": 5, "feature_fraction": 0.9, "is_unbalance": True,
    "seed": 7, "deterministic": True, "num_threads": 1, "verbose": -1,
}
NUM_ROUNDS = 150


def threshold_for_budget(human_scores, budget):
    """Smallest threshold that blocks at most `budget` of these humans."""
    if len(human_scores) == 0:
        return 0.5
    t = float(np.quantile(human_scores, 1 - budget, method="higher"))
    return min(t + 1e-6, 0.999999)


def split(lab, random_split):
    if random_split:
        return train_test_split(lab, test_size=0.3, stratify=lab["label"], random_state=7)
    lab = lab.sort_values("ts")
    cut = int(len(lab) * 0.7)
    return lab.iloc[:cut], lab.iloc[cut:]


def baseline(train, valid, feats):
    num = [f for f in feats if f not in CATEGORICAL]
    pre = ColumnTransformer([
        ("num", make_pipeline(SimpleImputer(strategy="median", add_indicator=True,
                                            keep_empty_features=True),
                              StandardScaler()), num),
        ("cat", OneHotEncoder(handle_unknown="ignore"), [c for c in CATEGORICAL if c in feats]),
    ])
    model = make_pipeline(pre, LogisticRegression(class_weight="balanced", max_iter=2000))
    model.fit(train[feats], train["label"])
    return model.predict_proba(valid[feats])[:, 1]


def fit(rows, feats):
    data = lgb.Dataset(rows[feats], rows["label"], categorical_feature=CATEGORICAL)
    return lgb.train(LGB_PARAMS, data, num_boost_round=NUM_ROUNDS)


def out_of_fold(lab, feats, k=5):
    """Score every labeled row with a model trained on the other folds (time-ordered blocks)."""
    oof = np.zeros(len(lab))
    for tr, te in KFold(k, shuffle=False).split(lab):
        oof[te] = fit(lab.iloc[tr], feats).predict(lab.iloc[te][feats])
    return oof


def auc(y, s):
    return f"{roc_auc_score(y, s):.3f}" if len(set(y)) == 2 else "n/a"


def operating_points(valid, scores):
    humans = scores[valid["label"].to_numpy() == 0]
    bots = scores[valid["label"].to_numpy() == 1]
    print("  FPR budget   threshold   bot recall (holdout)")
    for budget in (0.002, 0.01, 0.02, 0.05):
        t = threshold_for_budget(humans, budget)
        print(f"  {budget:>9.1%}   {t:>9.3f}   {(bots >= t).mean():>7.0%}")


def main():
    parser = argparse.ArgumentParser(description="Train the session model.")
    parser.add_argument("--round", type=int, choices=(1, 2), required=True)
    parser.add_argument("--include-leaky", action="store_true",
                        help="add label-source features (demonstrates leakage)")
    parser.add_argument("--random-split", action="store_true",
                        help="random instead of temporal split (demonstrates optimism)")
    parser.add_argument("--fpr-budget", type=float, default=FPR_BUDGET)
    args = parser.parse_args()

    started = time.perf_counter()
    hist = history.load()
    df = build_dataset(hist, with_cohort=args.round >= 2)
    if df.empty:
        sys.exit("No purchase attempts in the history yet. Run: python tools/simulate.py")
    # v1 is the day-one model: honeypot and login labels only. Analyst labels arrive in Round 2.
    df["label"] = weak_labels(df, hist["accounts"], manual=args.round >= 2)
    os.makedirs(ARTIFACTS, exist_ok=True)
    df.to_parquet(os.path.join(ARTIFACTS, "reference_features.parquet"), index=False)

    feats = list(FEATURE_SETS[args.round]) + (LEAKY_FEATURES if args.include_leaky else [])
    lab = df[df["label"].notna()].copy()
    lab["label"] = lab["label"].astype(int)
    train, valid = split(lab, args.random_split)
    print(f"=== Model v{args.round}: {len(feats)} features, {len(df)} sessions, "
          f"{len(lab)} labeled ({int(lab['label'].sum())} bot / {int((lab['label'] == 0).sum())} human) ===")
    print(f"  split: {'RANDOM' if args.random_split else 'temporal'} -> "
          f"train {len(train)}, validate {len(valid)}\n")

    # 1) Evaluation: train on the past, score the future. Honest, and pessimistic
    #    when the newest labels are a campaign the past never saw.
    lr_scores = baseline(train, valid, feats)
    scores = fit(train, feats).predict(valid[feats])
    print("  Holdout (train on older sessions, score the newest):")
    print(f"  ROC-AUC  logistic regression {auc(valid['label'], lr_scores)}"
          f"   LightGBM {auc(valid['label'], scores)}\n")
    operating_points(valid, scores)

    # 2) Deployment: refit on ALL labels, so the newest campaign is learned too.
    #    The threshold comes from out-of-fold scores of verified humans:
    #    each human is scored by a model that never saw them.
    ordered = lab.sort_values("ts")
    oof = out_of_fold(ordered, feats)
    humans = oof[ordered["label"].to_numpy() == 0]
    threshold = threshold_for_budget(humans, args.fpr_budget)
    if threshold < MIN_THRESHOLD:
        print(f"\n  WARNING: every verified human scores below {threshold:.4f}: the budget cannot place"
              f" the line.\n     Easy labels make a separable problem. Using the floor {MIN_THRESHOLD}.")
        threshold = MIN_THRESHOLD
    booster = fit(lab, feats)
    bots = scores[valid["label"].to_numpy() == 1]
    print(f"\n  deployed model: refit on all {len(lab)} labeled sessions")
    print(f"  FPR budget {args.fpr_budget:.1%} on {len(humans)} out-of-fold verified humans "
          f"-> threshold {threshold:.3f}  (holdout bot recall at it: {(bots >= threshold).mean():.0%})")

    gain = pd.Series(booster.feature_importance("gain"), index=feats).sort_values(ascending=False)
    print("\n  top features by gain: " + ", ".join(gain.index[:6]))

    if args.include_leaky or args.random_split:
        print("\n  demo run: model NOT saved. Compare the AUC with a normal run.")
        return
    name = f"model_v{args.round}"
    booster.save_model(os.path.join(ARTIFACTS, f"{name}.txt"))
    meta = {"version": args.round, "features": feats, "categorical": CATEGORICAL,
            "threshold": threshold, "fpr_budget": args.fpr_budget,
            "trained_at": time.time(), "n_train": len(train), "n_valid": len(valid),
            "holdout_auc": float(roc_auc_score(valid["label"], scores)) if valid["label"].nunique() == 2 else None,
            "train_seconds": round(time.perf_counter() - started, 2)}
    with open(os.path.join(ARTIFACTS, f"{name}.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    print(f"\n  saved artifacts/{name}.txt + .json  ({meta['train_seconds']}s). "
          f"The store reloads it on the next purchase.")


if __name__ == "__main__":
    main()
