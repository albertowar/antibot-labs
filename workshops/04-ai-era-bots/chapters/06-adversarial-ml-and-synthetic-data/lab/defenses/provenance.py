"""
W4 Ch6 — Round 3 Defense: sanitize the training set (Section 6.5)

The poisoning attack (attacks/round3_poison.py) injects a burst of
honeypot-hitting sessions that are shaped like real privacy-browser users.
The weak rule labels them "bot" (they really did hit the honeypot), so a
naive retrain learns "privacy-browser-shaped = bot" and starts blocking the
real privacy users. The labels are not wrong; the data is poisoned.

The defense is provenance: do not trust a label just because the rule
fired. Genuine honeypot-hitting bots are mostly cloud scrapers that look
nothing like a verified human. A cluster of honeypot hits that look exactly
like a legitimate cohort is the signature of a poisoning burst, so drop it
from training (demote it to unlabeled) before you fit.

This is the STUB. It retrains on everything, poison included (it keeps the
Round 2 robustness — monotone + adversarial — but adds no sanitization), so
model v4 blocks real privacy users.

  TODO (Round 3): implement `sanitize()`.
    Flag honeypot-labelled rows that (a) carry a real fingerprint
    (has_fp == 1) and (b) look like a verified human to the anomaly detector
    (anomaly score at or below its human threshold). Those are the poison:
    real bots that trip a honeypot do not look like your customers. Set
    their label to NaN so training ignores them.
  Re-run the checkpoint and watch the privacy_browser block rate fall back
  under budget.

Honest cost: sanitization can also drop a genuinely rare bot that happens to
look human, and if you are too aggressive you throw away real signal. It
trades a little recall for not being weaponized against your own users.

Reference: solutions/round3/defenses/provenance.py.

Run:
    python defenses/provenance.py            # writes artifacts/model_v4.*
"""

import os
import sys

import numpy as np
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
    return pd.read_parquet(ADVERSARIAL) if os.path.exists(ADVERSARIAL) else pd.DataFrame()


def sanitize(df, label):
    """STUB: no sanitization. The poison stays in the bot class."""
    # TODO (Round 3): demote the poison cluster to unlabeled (see docstring).
    return label


def main():
    df, label, feats = build()
    label = sanitize(df, label)
    booster, meta = retrain.deploy(df, label, feats, stage="sanitized",
                                   monotone=retrain.HARD_TELLS, extra_bot=load_adversarial(),
                                   note="stub: no provenance sanitization")
    print(f"=== Sanitized model (STUB): {meta['n_bot']} bot / {meta['n_human']} human, "
          f"threshold {meta['threshold']:.3f} ===")
    print("  Poison left in: the model will block real privacy-browser users.")
    print("  Implement sanitize() (or see solutions/round3/defenses/provenance.py).")


if __name__ == "__main__":
    main()
