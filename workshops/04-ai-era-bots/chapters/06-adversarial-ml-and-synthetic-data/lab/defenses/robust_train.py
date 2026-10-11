"""
W4 Ch6 — Round 2 Defense: a model that resists the evasion (Section 6.4)

The surrogate-guided evasion (attacks/round2_evade.py) buys diverse real
fingerprints and residential IPs, so cohort features see nothing and every
session looks human. What it cannot hide is a residual regularity in its
"humanized" behavior. Two levers turn that into a defense:

  1. Adversarial training: fold the red team's captured evasive sessions
     (data/adversarial.parquet, written by round2_evade) back into the
     labelled set as confirmed bots, so the model learns the residual tell.
  2. Monotone constraints: forbid the model from lowering its score when a
     hard tell is switched on (see retrain.HARD_TELLS), so the attacker
     cannot trade a datacenter exit or a missing Accept-Language for a pile
     of human-looking features.

This is the STUB. It retrains the model with NO adversarial examples and NO
constraints, so model v3 is just v2 under a new name and the evasion still
walks through.

  TODO (Round 2): make this robust.
    - load data/adversarial.parquet if present and pass it as `extra_bot`
    - pass `monotone=retrain.HARD_TELLS`
  Then re-run round2_evade and watch the evasion success collapse — and
  watch the checkpoint's real-user column for the cost of the constraints.

Reference: solutions/round2/defenses/robust_train.py.

Run:
    python defenses/robust_train.py          # writes artifacts/model_v3.*
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


def main():
    df, label, feats = build()
    # STUB: plain retrain, no adversarial examples, no constraints.
    booster, meta = retrain.deploy(df, label, feats, stage="robust",
                                   monotone=None, extra_bot=None,
                                   note="stub: no adversarial training, no monotone")
    print(f"=== Robust model (STUB): {meta['n_bot']} bot / {meta['n_human']} human, "
          f"threshold {meta['threshold']:.3f} ===")
    print("  No adversarial examples, no monotone constraints: the evasion still works.")
    print("  Implement the TODOs (or see solutions/round2/defenses/robust_train.py).")


if __name__ == "__main__":
    main()
