"""
W4 Ch6 — Round 4 Defense: SMOTE the rare minority (reference solution)

See the stub (defenses/augment.py) for the rationale, the license note on
CTGAN/SDV vs synthcity, and the false-positive cost.
"""

import os
import sys

import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE

sys.path.insert(0, os.path.dirname(__file__))

import retrain  # noqa: E402
from features import CATEGORICAL  # noqa: E402
from netinfo import ASN_TYPES  # noqa: E402
from provenance import build, load_adversarial, sanitize  # noqa: E402

RESIDENTIAL = ASN_TYPES.index("residential")
MOBILE = ASN_TYPES.index("mobile")


def _minority_mask(df, label):
    """Labelled bots that look like real-device mobile/residential sessions:
    the thin corner the honeypot labels barely cover."""
    asn = df["asn_type"]
    return ((label == 1)
            & (df["has_fp"].fillna(0) == 1)
            & (df["software_gpu"].fillna(0) != 1)
            & (df["has_beh"].fillna(0) == 1)
            & (asn.isin([RESIDENTIAL, MOBILE])))


def synthesize(df, label, feats, target=60, seed=7):
    """SMOTE the rare corner up to `target` rows; return the synthetic ones."""
    lab = df[label.notna()].copy()
    lab_label = label[label.notna()].astype(int)
    minority = _minority_mask(df, label)[label.notna()].astype(int).to_numpy()
    n_min = int(minority.sum())
    if n_min < 2:
        print("  augment: too few rare-class labels to synthesize; skipping")
        return pd.DataFrame()

    num = [f for f in feats if f not in CATEGORICAL]
    X = lab[num].apply(lambda c: c.fillna(c.median()), axis=0).fillna(0.0).to_numpy()
    want = max(n_min + 1, min(target, (minority == 0).sum()))
    sm = SMOTE(random_state=seed, sampling_strategy={1: want, 0: int((minority == 0).sum())},
               k_neighbors=min(5, n_min - 1))
    Xr, yr = sm.fit_resample(X, minority)
    # The synthetic minority rows are appended after the originals by imblearn
    synth_X = Xr[len(X):][yr[len(X):] == 1]
    if len(synth_X) == 0:
        return pd.DataFrame()
    out = pd.DataFrame(synth_X, columns=num)
    # Categorical asn_type: put synthetic rows in the rare corner (residential)
    out["asn_type"] = RESIDENTIAL
    out["label"] = 1
    print(f"  augment: synthesized {len(out)} rare-class rows from {n_min} real examples (SMOTE)")
    return out


def main():
    df, label, feats = build()
    label = sanitize(df, label)
    synth = synthesize(df, label, feats)
    extra = pd.concat([load_adversarial(), synth], ignore_index=True) \
        if not synth.empty else load_adversarial()
    booster, meta = retrain.deploy(df, label, feats, stage="augmented",
                                   monotone=retrain.HARD_TELLS, extra_bot=extra,
                                   note="SMOTE minority + provenance + monotone + adversarial")
    print(f"=== Augmented model: {meta['n_bot']} bot / {meta['n_human']} human, "
          f"threshold {meta['threshold']:.3f}, holdout AUC {meta['holdout_auc']} ===")


if __name__ == "__main__":
    main()
