"""
Round 2 defense: a model that resists the evasion (reference solution)

The surrogate-guided evasion (attacks/round2_evade.py) buys diverse real fingerprints and a different
residential or cloud exit for every session, so the cohort features see nothing and every session looks
human to the baseline. What it cannot hide is a residual regularity in its "humanized" behaviour: tighter
speed and typing variation than any real person, straighter paths. Two levers turn that into a defense:

  1. Adversarial training: fold the red team's captured evasive sessions (data/adversarial.parquet,
     written by `python tools/simulate.py --wave round2_evade`) back into the labelled set as confirmed
     bots, so the model learns the residual tell. They are the defender's own traffic, labelled by the one
     party that knows for certain: the red team.
  2. Monotone constraints: forbid the model from LOWERING its score when a hard tell is switched on (see
     retrain.HARD_TELLS), so the attacker cannot trade a missing Accept-Language or a software GPU for a pile
     of human-looking features.

Honest cost, shown by the checkpoint's customer table: the constraints and the extra bots move the boundary
for everyone. A customer whose session is rare (a keyboard-only user, a privacy browser) can land on the
wrong side of it, and the model only knows the evasion you showed it. A different evasion needs new
examples: this is an arms race, not a fix.
"""

import os
import sys

import pandas as pd

from . import retrain, waves
from .features import build_dataset
from .labels import weak_labels

ADVERSARIAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "adversarial.parquet")


def build(stage="robust"):
    """(features, weak labels) of the history this stage trains on (defenses/waves.py)."""
    hist = waves.for_stage(stage)
    df = build_dataset(hist, with_cohort=True)
    if df.empty:
        sys.exit("No purchase attempts in the history yet. Run: python tools/simulate.py")
    return df, weak_labels(df, hist["accounts"])


def load_adversarial():
    """The red team's captured evasive sessions, labelled bot. Empty if no evasion wave has run."""
    return pd.read_parquet(ADVERSARIAL) if os.path.exists(ADVERSARIAL) else pd.DataFrame()


def main():
    df, label = build("robust")
    extra = load_adversarial()
    booster, meta = retrain.deploy(df, label, retrain.FEATURES, version=3, stage="robust",
                                   monotone=retrain.HARD_TELLS, extra_bot=extra,
                                   note="adversarial training + monotone constraints")
    retrain.report(f"Robust model v3 ({len(extra)} adversarial examples)", meta)
    print(f"  monotone constraints on {len(retrain.HARD_TELLS)} hard tells")


if __name__ == "__main__":
    main()
