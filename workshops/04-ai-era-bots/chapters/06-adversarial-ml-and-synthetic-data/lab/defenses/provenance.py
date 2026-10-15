"""
Round 3 defense: sanitize the training set  [YOUR FILE]
Round 3 defense: sanitize the training set

The poisoning attack (attacks/round3_poison.py) injects a burst of honeypot-hitting sessions that are
shaped like real privacy-browser users. The weak rule labels them "bot" (they really did hit the honeypot),
so a naive retrain learns "privacy-browser-shaped = bot" and starts refusing the real privacy users. The
labels are not wrong; the data is poisoned.

The defense is provenance: do not trust a label just because the rule fired. Genuine honeypot-hitting bots
are mostly cloud scrapers that look nothing like a verified human. A cluster of honeypot hits that look
exactly like a legitimate cohort is the signature of a poisoning burst, so drop it from training (demote it
to unlabeled) before you fit.

Honest cost: sanitization can also drop a genuinely rare bot that happens to look human, and if you are too
aggressive you throw away real signal. It trades a little recall for not being weaponized against your own
users. And the test below leans on the anomaly detector's allowlist for privacy browsers
(anomaly.KNOWN_BENIGN_GPUS): the same allowlist a bot author can read and copy.

This is the STUB. It retrains on everything, poison included (it keeps the Round 2 hardening, the monotone
constraints and the adversarial examples, but adds no sanitization), so model v4 refuses real privacy users.

TODO (Round 3): implement sanitize().
  Flag the honeypot-labelled rows (label == 1 and honeypot_hits > 0) that (a) carry a real fingerprint
  (has_fp == 1) and (b) look like a verified human to the anomaly detector (anomaly score at or below its
  threshold: detector.score(df) <= detector.threshold). Those are the poison: real bots that trip a
  honeypot do not look like your customers. Set their label to NaN so training ignores them.
Then run the checkpoint and watch the privacy_browser row fall back under budget.

Run:
    python tools/simulate.py --wave round3_poison     # the burst reaches your history first
    python -m defenses.provenance                     # writes artifacts/model_v4.*
Fell behind? python tools/checkpoint.py --round 3 --catch-up
"""

import numpy as np

from . import anomaly, models, retrain
from .robust_train import build, load_adversarial


def detector(df, label):
    """The human-only anomaly detector deployed with the model (fitted on the spot if the file is missing)."""
    try:
        return anomaly.AnomalyModel(models.load_anomaly_meta())
    except (OSError, FileNotFoundError):
        model, _ = anomaly.fit(df.assign(label=label), anomaly.FPR_BUDGET)
        return model


def sanitize(df, label):
    """STUB: no sanitization. The poison stays in the bot class."""
    # TODO (Round 3): demote the poison cluster to unlabeled (see the module docstring).
    return label


def main():
    df, label = build("sanitized")
    label = sanitize(df, label)
    booster, meta = retrain.deploy(df, label, retrain.FEATURES, version=4, stage="sanitized",
                                   monotone=retrain.HARD_TELLS, extra_bot=load_adversarial(),
                                   note="stub: no provenance sanitization")
    retrain.report("Sanitized model v4 (STUB)", meta)
    print("  Poison left in: the model will refuse real privacy-browser users.")
    print("  Implement sanitize() (or see solutions/round3/defenses/provenance.py).")


if __name__ == "__main__":
    main()
