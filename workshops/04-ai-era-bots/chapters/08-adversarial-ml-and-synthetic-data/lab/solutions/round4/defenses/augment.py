"""
Round 4 defense: synthetic data for the rare class (reference solution)
Round 4 defense: synthetic data for the rare class

The slow mobile reseller (attacks/round4_rareclass.py) lives where your labels are thin: real-device mobile
sessions behind residential exits that almost never hit a honeypot and never sign in. The labelled bot class
is full of cloud scrapers, so the model has nothing to learn the corner from and waves the family through.
This is class imbalance, not evasion.

Synthetic data fills the corner. We take the few labelled examples of the rare family and oversample them
with SMOTE (imbalanced-learn), interpolating new points between real ones, then add the synthetic rows to
training so the model sees enough of the family to draw a boundary.

This chapter uses SMOTE because it is free, open source and lightweight. Richer generators exist, CTGAN and
TVAE (SDV), which model joint distributions better, but SDV ships under the Business Source License, which is
not OSI open source, so it stays a slide, not a lab dependency. synthcity (Apache-2.0) is the FOSS alternative
if you need a GAN/VAE and can afford PyTorch.

Honest cost: interpolated points can spill into the real mobile region and cost false positives, and a
handful of seeds cannot describe a family: SMOTE amplifies what you labelled, including its accidents.
"""

import numpy as np
import pandas as pd

from . import netinfo, retrain
from .features import CATEGORICAL
from .provenance import build, load_adversarial, sanitize

RESIDENTIAL = netinfo.ASN_TYPES.index("residential")
MOBILE = netinfo.ASN_TYPES.index("mobile")


def _minority_mask(df, label):
    """Labelled bots that look like real-device mobile/residential sessions: the thin corner the honeypot
    labels barely cover."""
    return ((label == 1)
            & (df["has_fp"].fillna(0) == 1)
            & (df["software_gpu"].fillna(0) != 1)
            & (df["has_beh"].fillna(0) == 1)
            & (df["asn_type"].isin([RESIDENTIAL, MOBILE])))


def synthesize(df, label, feats, target=60, seed=7):
    """SMOTE the rare corner up to `target` rows; return the synthetic ones."""
    lab = df[label.notna()].copy()
    minority = _minority_mask(df, label)[label.notna()].astype(int).to_numpy()
    n_min = int(minority.sum())
    if n_min < 2:
        print("  augment: too few rare-class labels to synthesize; skipping")
        return pd.DataFrame()

    from imblearn.over_sampling import SMOTE
    num = [f for f in feats if f not in CATEGORICAL]
    X = lab[num].apply(lambda c: c.fillna(c.median()), axis=0).fillna(0.0).to_numpy()
    want = max(n_min + 1, min(target, int((minority == 0).sum())))
    sm = SMOTE(random_state=seed, sampling_strategy={1: want, 0: int((minority == 0).sum())},
               k_neighbors=min(5, n_min - 1))
    Xr, yr = sm.fit_resample(X, minority)
    # imblearn appends the synthetic rows after the originals
    synth_X = Xr[len(X):][yr[len(X):] == 1]
    if len(synth_X) == 0:
        return pd.DataFrame()
    out = pd.DataFrame(synth_X, columns=num)
    out["asn_type"] = RESIDENTIAL     # the rare corner is a residential exit; real phones sit on mobile ones
    out["label"] = 1
    print(f"  augment: synthesized {len(out)} rare-class rows from {n_min} real examples (SMOTE)")
    return out


def main():
    df, label = build("augmented")
    label = sanitize(df, label)
    synth = synthesize(df, label, retrain.FEATURES)
    adversarial = load_adversarial()
    extra = pd.concat([adversarial, synth], ignore_index=True) if not synth.empty else adversarial
    booster, meta = retrain.deploy(df, label, retrain.FEATURES, version=5, stage="augmented",
                                   monotone=retrain.HARD_TELLS, extra_bot=extra,
                                   note="SMOTE minority + provenance + monotone + adversarial")
    retrain.report("Augmented model v5", meta)


if __name__ == "__main__":
    main()
