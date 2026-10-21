"""
Round 4 defense: synthetic data for the rare class  [YOUR FILE]
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

This is the STUB. It retrains with no augmentation (it keeps the Round 2 and 3 defenses), so the rare family
still gets through.

TODO (Round 4): implement synthesize().
  Pick the minority corner among the labelled bots (real device: has_fp and has_beh, no software GPU, a
  residential or mobile asn_type; _minority_mask() is given). SMOTE it up and return the synthetic rows,
  labelled bot, for `extra_bot`.
Then run the checkpoint: the family's success rate falls, and watch the mobile row of the customer table,
because interpolated points can land on real phones.

Run:
    python tools/simulate.py --wave round4_rareclass  # the family reaches your history first
    python -m defenses.augment                        # writes artifacts/model_v5.*
Fell behind? python tools/checkpoint.py --round 4 --catch-up
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


def synthesize(df, label, feats):
    """STUB: no synthetic data. Return an empty frame."""
    # TODO (Round 4): SMOTE the rare minority corner and return the new rows.
    return pd.DataFrame()


def main():
    df, label = build("augmented")
    label = sanitize(df, label)
    synth = synthesize(df, label, retrain.FEATURES)
    adversarial = load_adversarial()
    extra = pd.concat([adversarial, synth], ignore_index=True) if not synth.empty else adversarial
    booster, meta = retrain.deploy(df, label, retrain.FEATURES, version=5, stage="augmented",
                                   monotone=retrain.HARD_TELLS, extra_bot=extra,
                                   note="stub: no synthetic augmentation")
    retrain.report("Augmented model v5 (STUB)", meta)
    print("  No synthetic minority: the rare family still gets through.")
    print("  Implement synthesize() (or see solutions/round4/defenses/augment.py).")


if __name__ == "__main__":
    main()
