"""
Round 3 defense: sanitize the training set (reference solution)
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
    """Demote the poison: honeypot-labelled rows with a real fingerprint that the anomaly detector scores as
    human-like (at or below its threshold)."""
    model = detector(df, label)
    anomalous = model.score(df)
    honeypot_bot = (label == 1) & (df["honeypot_hits"].fillna(0) > 0)
    looks_human = (df["has_fp"].fillna(0) == 1) & (anomalous <= model.threshold)
    poison = honeypot_bot & looks_human
    out = label.copy()
    out[poison] = np.nan
    print(f"  provenance: demoted {int(poison.sum())} human-looking honeypot hits (suspected poisoning burst) to unlabeled")
    return out


def main():
    df, label = build("sanitized")
    label = sanitize(df, label)
    booster, meta = retrain.deploy(df, label, retrain.FEATURES, version=4, stage="sanitized",
                                   monotone=retrain.HARD_TELLS, extra_bot=load_adversarial(),
                                   note="provenance-sanitized + monotone + adversarial")
    retrain.report("Sanitized model v4", meta)


if __name__ == "__main__":
    main()
