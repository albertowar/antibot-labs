"""
The deployed model you start with (infrastructure, not a student exercise)

This chapter picks up where W2 Ch7 left off, rebuilt here so it runs on its own: a LightGBM model on
per-session and cohort features, weak-labelled from honeypot hits and loyal sign-ins, its threshold
set from a false-positive budget on out-of-fold verified humans (model v2), paired with the human-only
anomaly detector (defenses/anomaly.py, W2 Ch7's Round 3). The labels come from the drop-day history
alone (waves.py: the "base" stage); no analyst has clustered anything, so this is the model a team
ships on day one.

It is the asset the attacker spends the chapter trying to steal, evade, poison and slip past.
Rounds 2 to 4 each retrain a hardened successor into its own file (model_v3 .. model_v5).

Run:
    python -m defenses.baseline_model        # writes artifacts/model_v2.* and artifacts/anomaly_v3.json
"""

import os
import sys

from . import anomaly, models, retrain, waves
from .features import build_dataset
from .labels import weak_labels


def main():
    hist = waves.for_stage("base")
    df = build_dataset(hist, with_cohort=True)
    if df.empty:
        sys.exit("No purchase attempts in the history yet. Run: python tools/simulate.py")
    label = weak_labels(df, hist["accounts"])
    booster, meta = retrain.deploy(df, label, retrain.FEATURES, version=2, stage="base",
                                   note="the deployed baseline: W2 Ch7's model v2, no analyst labels")
    retrain.report("Baseline model v2", meta)

    detector, hold = anomaly.fit(df.assign(label=label), anomaly.FPR_BUDGET)
    os.makedirs(models.ARTIFACTS, exist_ok=True)
    detector.save()
    print(f"=== Anomaly detector: device-claim likelihood on {detector.n} verified-human sessions, "
          f"threshold {detector.threshold:.2f} nats ===")
    print("  saved artifacts/anomaly_v3.json")


if __name__ == "__main__":
    main()
