"""
W4 Ch6 — Round 3 Defense: provenance sanitization (reference solution)

Demote honeypot-labelled rows that look like a verified human to the anomaly
detector. See the stub (defenses/provenance.py) for the rationale and cost.
"""

import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))

import anomaly as anomaly_mod  # noqa: E402
import retrain  # noqa: E402
from anomaly import AnomalyModel  # noqa: E402
from features import FEATURE_SETS, build_dataset  # noqa: E402
from labels import weak_labels  # noqa: E402
from store import make_engine  # noqa: E402

ADVERSARIAL = os.path.join(os.path.dirname(__file__), "..", "data", "adversarial.parquet")


def build():
    feats = list(FEATURE_SETS[2])
    engine = make_engine()
    with engine.connect() as conn:
        df = build_dataset(conn, with_cohort=True)
        accounts = pd.read_sql("SELECT * FROM accounts", conn)
    if df.empty:
        sys.exit("No checkouts yet. Run tools/simulate.py first.")
    label = weak_labels(df, accounts)
    return df, label, feats


def load_adversarial():
    return pd.read_parquet(ADVERSARIAL) if os.path.exists(ADVERSARIAL) else pd.DataFrame()


def _anomaly_model(df, label):
    try:
        return AnomalyModel.load()
    except (OSError, ValueError):
        model, _ = anomaly_mod.fit(df.assign(label=label), anomaly_mod.FPR_BUDGET)
        return model


def sanitize(df, label):
    """Demote the poison: honeypot-labelled rows with a real fingerprint that
    the anomaly detector scores as human-like (at or below its threshold)."""
    model = _anomaly_model(df, label)
    anomaly = model.score(df)
    honeypot_bot = (label == 1) & (df["honeypot_hits"].fillna(0) > 0)
    looks_human = (df["has_fp"].fillna(0) == 1) & (anomaly <= model.threshold)
    poison = honeypot_bot & looks_human
    out = label.copy()
    out[poison] = np.nan
    print(f"  provenance: demoted {int(poison.sum())} human-looking honeypot hits "
          f"(suspected poisoning burst) to unlabeled")
    return out


def main():
    df, label, feats = build()
    label = sanitize(df, label)
    booster, meta = retrain.deploy(df, label, feats, stage="sanitized",
                                   monotone=retrain.HARD_TELLS, extra_bot=load_adversarial(),
                                   note="provenance-sanitized + monotone + adversarial")
    print(f"=== Sanitized model: {meta['n_bot']} bot / {meta['n_human']} human, "
          f"threshold {meta['threshold']:.3f}, holdout AUC {meta['holdout_auc']} ===")


if __name__ == "__main__":
    main()
