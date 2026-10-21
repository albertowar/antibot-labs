"""
Round 2 defense: a model that resists the evasion  [YOUR FILE]

The surrogate-guided evasion (attacks/round2_evade.py) buys diverse real fingerprints and a
different residential or cloud exit for every session, so the cohort features see nothing and
every session looks human to the baseline. What it cannot hide is a residual regularity in its
"humanized" behaviour: tighter speed and typing variation than any real person, straighter paths.
Two levers turn that into a defense:

  1. Adversarial training: fold the red team's captured evasive sessions (data/adversarial.parquet,
     written by `python tools/simulate.py --wave round2_evade`) back into the labelled set as
     confirmed bots — the defender's own traffic, labelled by the one party that knows for certain.
  2. Monotone constraints: forbid the model from LOWERING its score when a hard tell is switched
     on (retrain.HARD_TELLS), so the attacker cannot trade a missing Accept-Language or a software
     GPU for a pile of human-looking features.

Honest cost, shown by the checkpoint's customer table: the constraints and the extra bots move the
boundary for everyone. A rare-but-real session (keyboard-only, a privacy browser) can land on the
wrong side, and the model only knows the evasion you showed it: a different evasion needs new
examples. An arms race, not a fix.

This is the STUB. It retrains model v3 on the same history with NEITHER lever: no adversarial
examples, no monotone constraints. The evasion wave sails through it, which is Round 2's "before".

TODO (Round 2): pull both levers in main().
  Load the captured wave with load_adversarial() and pass it as extra_bot=, and pass
  monotone=retrain.HARD_TELLS, to retrain.deploy(...). Then run the checkpoint and compare the
  evasion's success and the customer table against the stub's.

Run:
    python tools/simulate.py --wave round2_evade      # the red team captures the evasion first
    python -m defenses.robust_train                   # writes artifacts/model_v3.*
Fell behind? python tools/checkpoint.py --round 2 --catch-up
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
    # TODO (Round 2): pass extra_bot=load_adversarial() and monotone=retrain.HARD_TELLS.
    booster, meta = retrain.deploy(df, label, retrain.FEATURES, version=3, stage="robust",
                                   note="stub: no adversarial examples, no monotone constraints")
    retrain.report("Robust model v3 (STUB: unhardened)", meta)
    print("  The evasion wave will sail through this model.")
    print("  Pull both levers (or see solutions/round2/defenses/robust_train.py).")


if __name__ == "__main__":
    main()
