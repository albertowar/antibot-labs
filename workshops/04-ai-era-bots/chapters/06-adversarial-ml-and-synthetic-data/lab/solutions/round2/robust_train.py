"""
W4 Ch6 — Round 2 Defense: robust model v3 (reference solution)

Adversarial training + monotone constraints. See the stub
(defenses/robust_train.py) for the full rationale and the cost caveat.
"""

import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))

import retrain  # noqa: E402
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
    if os.path.exists(ADVERSARIAL):
        return pd.read_parquet(ADVERSARIAL)
    return pd.DataFrame()


def main():
    df, label, feats = build()
    extra = load_adversarial()
    booster, meta = retrain.deploy(df, label, feats, stage="robust",
                                   monotone=retrain.HARD_TELLS, extra_bot=extra,
                                   note="adversarial training + monotone constraints")
    print(f"=== Robust model: {meta['n_bot']} bot / {meta['n_human']} human "
          f"({len(extra)} adversarial), threshold {meta['threshold']:.3f} ===")
    print(f"  monotone constraints on {len(retrain.HARD_TELLS)} hard tells; "
          f"holdout AUC {meta['holdout_auc']}")


if __name__ == "__main__":
    main()
