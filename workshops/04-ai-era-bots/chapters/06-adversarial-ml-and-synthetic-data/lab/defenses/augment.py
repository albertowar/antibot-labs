"""
W4 Ch6 — Round 4 Defense: synthetic data for the rare class (Section 6.6)

The slow mobile reseller (attacks/round4_rareclass.py) lives where your
labels are thin: real-device mobile sessions that almost never hit a
honeypot and never log in. The labelled bot class is full of cloud
scrapers, so the model has nothing to learn the corner from and waves the
family through. This is class imbalance, not evasion.

Synthetic data fills the corner. We take the few labelled examples of the
rare family and oversample them with SMOTE (imbalanced-learn), interpolating
new points between real ones, then add the synthetic rows to training so the
model sees enough of the family to draw a boundary.

This chapter uses SMOTE because it is free, open source and lightweight.
Richer generators exist — CTGAN and TVAE (SDV), which model joint
distributions better — but SDV ships under the Business Source License,
which is not OSI open source, so it stays a slide, not a lab dependency.
synthcity (Apache-2.0) is the FOSS alternative if you need a GAN/VAE and can
afford PyTorch.

This is the STUB. It retrains with no augmentation (keeps Round 2–3
defenses), so the rare family still gets through.

  TODO (Round 4): implement `synthesize()`.
    Pick the minority corner among labelled bots (real-device, mobile or
    residential, has_beh). SMOTE it up and return the synthetic rows,
    labelled bot, for `extra_bot`.
  Re-run the checkpoint: rare-class recall jumps — and watch the mobile
  real-user column, because interpolated points can spill into the real
  mobile region and cost you false positives.

Reference: solutions/round4/defenses/augment.py.

Run:
    python defenses/augment.py               # writes artifacts/model_v5.*
"""

import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))

import retrain  # noqa: E402
from provenance import build, load_adversarial, sanitize  # noqa: E402


def synthesize(df, label, feats):
    """STUB: no synthetic data. Return an empty frame."""
    # TODO (Round 4): SMOTE the rare minority corner and return the new rows.
    return pd.DataFrame()


def main():
    df, label, feats = build()
    label = sanitize(df, label)
    synth = synthesize(df, label, feats)
    extra = pd.concat([load_adversarial(), synth], ignore_index=True) \
        if not synth.empty else load_adversarial()
    booster, meta = retrain.deploy(df, label, feats, stage="augmented",
                                   monotone=retrain.HARD_TELLS, extra_bot=extra,
                                   note="stub: no synthetic augmentation")
    print(f"=== Augmented model (STUB): {meta['n_bot']} bot / {meta['n_human']} human, "
          f"threshold {meta['threshold']:.3f} ===")
    print("  No synthetic minority: the rare family still gets through.")
    print("  Implement synthesize() (or see solutions/round4/defenses/augment.py).")


if __name__ == "__main__":
    main()
