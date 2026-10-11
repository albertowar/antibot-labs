"""
W4 Ch6 — The deployed model you start with (Section 6.2)

This chapter picks up where W2 Ch7 left off: a LightGBM model on per-session
and cohort features, weak-labelled from honeypots and loyal logins, with its
threshold set from a false-positive budget on out-of-fold verified humans.
It is paired with the human-only anomaly detector (defenses/anomaly.py).

`baseline_model.py` builds exactly that and writes it to the single
`artifacts/model.txt` the demo site hot-reloads. Rounds 2–4 overwrite the
same file with a hardened version; the site reloads it without a restart.

This is infrastructure, not a student exercise — it is the asset the attacker
spends the chapter trying to steal, evade, poison and slip past.

Run:
    python defenses/baseline_model.py        # writes artifacts/model.(txt|json)
    python defenses/anomaly.py               # writes artifacts/anomaly_v3.json
"""

import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))

import retrain  # noqa: E402
from features import FEATURE_SETS, build_dataset  # noqa: E402
from labels import weak_labels  # noqa: E402
from store import make_engine  # noqa: E402


def main():
    feats = list(FEATURE_SETS[2])   # per-session + cohort, the W2 Ch7 v2 feature set
    engine = make_engine()
    with engine.connect() as conn:
        df = build_dataset(conn, with_cohort=True)
        accounts = pd.read_sql("SELECT * FROM accounts", conn)
    if df.empty:
        sys.exit("No checkouts yet. Run tools/simulate.py first.")
    label = weak_labels(df, accounts)
    booster, meta = retrain.deploy(df, label, feats, stage="base",
                                   monotone=None, extra_bot=None,
                                   note="base deployed model (W2 Ch7 end state)")
    print(f"=== Base model: {meta['n_bot']} bot / {meta['n_human']} human labeled, "
          f"threshold {meta['threshold']:.3f}, holdout AUC {meta['holdout_auc']} ===")
    print("  saved artifacts/model.(txt|json). Now fit the anomaly detector:")
    print("    python defenses/anomaly.py")


if __name__ == "__main__":
    main()
