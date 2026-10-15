"""
Retraining, the boring way

    python tools/train.py --weeks 1-3 --labels weak             -> registers v1 as a candidate
    python tools/train.py --weeks 1-4 --labels weak+analyst     -> v3, with the analyst's labels

Reads the decision log, labels it (labels.py), builds the feature matrix
(features.py), trains a small LightGBM, holds out 25% to report AUC and the
false-positive rate on weak humans, and picks the two thresholds from a
false-positive *budget* on the held-out humans (the W2 Ch7 rule: decide what
you will do to real users first, then read off the score):

    t_suspicious   the score below which 97%  of held-out humans fall
    t_bot          the score below which 99.5% of held-out humans fall

The candidate is written to the registry with its thresholds and metrics,
and nothing else happens. Promotion is gate.py's job, on purpose: the
script that trains a model must never be the script that ships it.

What this script cannot know: whether its labels are true. A model is only
as honest as the labels, and the weak labels say "human" about every bot
that got through last week (Round 3).
"""

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import labels  # noqa: E402
from report import decisions, read_log  # noqa: E402  (puts the lab root on sys.path)
from defenses import mlfeatures as features  # noqa: E402
from defenses import registry  # noqa: E402

PARAMS = {"objective": "binary", "num_leaves": 7, "learning_rate": 0.1, "min_data_in_leaf": 5,
          "feature_fraction": 0.9, "bagging_fraction": 0.9, "bagging_freq": 1, "verbose": -1,
          "seed": 2026, "deterministic": True, "num_threads": 1}
ROUNDS = 80
FP_BUDGET_SUSPICIOUS = 0.03   # challenge at most 3% of held-out humans
FP_BUDGET_BOT = 0.005         # block at most 0.5%


def parse_weeks(spec):
    lo, _, hi = spec.partition("-")
    return list(range(int(lo), int(hi or lo) + 1))


def dataset(weeks, source):
    entries = [e for e in decisions(read_log()) if e.get("week") in weeks]
    rows = labels.labelled(entries, source)
    X = np.array([features.from_log(e) for e, _ in rows], dtype=float)
    y = np.array([1 if l == "bot" else 0 for _, l in rows])
    return X, y, rows


def thresholds(p_humans):
    t_sus = float(np.quantile(p_humans, 1 - FP_BUDGET_SUSPICIOUS)) if len(p_humans) else 0.5
    t_bot = float(np.quantile(p_humans, 1 - FP_BUDGET_BOT)) if len(p_humans) else 0.9
    t_sus = min(max(t_sus, 0.30), 0.90)
    t_bot = min(max(t_bot, t_sus + 0.05), 0.98)
    return round(t_sus, 3), round(t_bot, 3)


def train(weeks, source):
    import lightgbm as lgb
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import train_test_split

    X, y, rows = dataset(weeks, source)
    if len(y) < 40 or y.sum() < 10 or (len(y) - y.sum()) < 10:
        raise SystemExit(f"Not enough labelled data: {len(y)} rows, {int(y.sum())} bots. "
                         "Replay more weeks or add labels.")
    X_tr, X_ho, y_tr, y_ho = train_test_split(X, y, test_size=0.25, stratify=y, random_state=7)
    booster = lgb.train(PARAMS, lgb.Dataset(X_tr, y_tr, feature_name=features.COLUMNS), ROUNDS)
    p_ho = booster.predict(X_ho)
    t_sus, t_bot = thresholds(p_ho[y_ho == 0])
    metrics = {
        "rows": int(len(y)), "bots": int(y.sum()),
        "auc": round(float(roc_auc_score(y_ho, p_ho)), 3) if len(set(y_ho)) > 1 else None,
        "recall_at_t_bot": round(float((p_ho[y_ho == 1] >= t_bot).mean()), 3),
        "fpr_at_t_bot": round(float((p_ho[y_ho == 0] >= t_bot).mean()), 4),
        "fpr_at_t_sus": round(float((p_ho[y_ho == 0] >= t_sus).mean()), 4),
    }
    version = registry.next_version()
    os.makedirs(registry.MODELS_DIR, exist_ok=True)
    booster.save_model(registry.model_path(version))
    registry.register(version, {"trained_on": weeks, "labels": source,
                                "t_suspicious": t_sus, "t_bot": t_bot, "metrics": metrics})
    importance = sorted(zip(features.COLUMNS, booster.feature_importance("gain")),
                        key=lambda kv: -kv[1])[:6]
    return version, metrics, importance


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--weeks", required=True, help="e.g. 1-3")
    parser.add_argument("--labels", default="weak", choices=["weak", "analyst", "weak+analyst"])
    args = parser.parse_args()
    weeks = parse_weeks(args.weeks)
    version, metrics, importance = train(weeks, args.labels)
    print(f"registered {version}: weeks {args.weeks}, labels {args.labels}")
    print("  " + ", ".join(f"{k} {v}" for k, v in metrics.items()))
    print("  top features by gain: " + ", ".join(f"{n} {g:.0f}" for n, g in importance))
    print(f"  it is a candidate. Shadow it (tools/roles.py shadow {version}) or gate it "
          f"(tools/gate.py --candidate {version}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
