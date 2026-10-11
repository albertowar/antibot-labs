"""
Chapter 7 — Anomaly detection: catching bots nobody labeled (Round 3, Section 7.4)

A supervised model can only recognise the bots in its labels. An anomaly
detector flips the question: learn what VERIFIED HUMANS look like and flag
whatever does not fit, including bot families you have never seen.

Model: how improbable are this session's DEVICE CLAIMS among verified humans?

    surprise = -log P(platform) - log P(gpu | platform) - log P(screen | platform)
               - Σ log P(flag) for each consistency flag

Probabilities are counted on verified-human sessions with add-one (Laplace)
smoothing, so a combination never seen still gets a small, finite
probability. A randomizer that draws each attribute independently produces
combinations no real device has (an Apple GPU on Win32, a phone with zero
touch points): very low probability, very high surprise. Each term is
readable on its own, so a flagged session comes with its reasons.

Why not Isolation Forest? We tried (Liu et al., 2008, a fine default for
continuous features). On these features it fails in two instructive ways:
  - it can only split on features that VARY in its training data. Verified
    humans almost never have a consistency flag set, so those columns are
    constant and the forest ignores them;
  - it cannot extrapolate. A combination rarer than anything in training
    scores the same as the rarest human it saw.
Pick the anomaly model for the shape of your features, not by name.

Behavior features are left out on purpose: human behavior varies so much
that it drowns the device signal, and the supervised model already covers
scripted behavior. `tz_ip_mismatch` is left out too: on its own it describes
VPN users and travellers, not bots.

Threshold: a false-positive budget on held-out verified humans, as in
train.py. Combination with the supervised score lives in scorer.py.

False-positive profile, read before you ship one:
  "Rare" is not "bot". Privacy browsers (generic GPU string, rounded screen
  sizes), Linux desktops, less common phones and brand-new devices are all
  rare among verified humans. An anomaly detector trained on your loyal
  customers flags exactly the people who look least like your loyal
  customers. Run --audit and look per cohort.

Run:
    python defenses/anomaly.py            # fit, pick threshold, save
    python defenses/anomaly.py --audit    # lab only: flag rate per true cohort
"""

import argparse
import json
import math
import os
import sys
from collections import Counter

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))

from features import build_dataset  # noqa: E402
from labels import load_truth, weak_labels  # noqa: E402
from store import make_engine  # noqa: E402

ARTIFACTS = os.path.join(os.path.dirname(__file__), "..", "artifacts")

FLAGS = ["ua_platform_mismatch", "gpu_platform_mismatch", "touch_platform_mismatch",
         "software_gpu", "webdriver", "input_platform_mismatch"]
MOBILE_PLATFORMS = ("iPhone", "iPad", "Linux armv")
# Known-benign rare signatures: Firefox resistFingerprinting reports this WebGL
# renderer and rounds the window size. Skipping the GPU and screen terms for it
# stops flagging privacy-browser users, and also hands attackers a disguise.
# Every allowlist entry is both.
# TODO (Round 3): empty this set, re-run `python defenses/anomaly.py --audit`,
# and look at the privacy_browser row. Then decide whether to put it back.
KNOWN_BENIGN_GPUS = {"Mozilla"}
FPR_BUDGET = 0.01


def input_mismatch(platform, mouse_moves, touches):
    """A phone that moves a mouse, or a desktop that only taps."""
    moves = 0 if pd.isna(mouse_moves) else mouse_moves
    taps = 0 if pd.isna(touches) else touches
    mobile = platform.startswith(MOBILE_PLATFORMS)
    return int((mobile and moves > 0) or (not mobile and taps > 0 and moves == 0))


def claims(row):
    """The device claims of one session, or None when it never ran JS."""
    combo = row.get("fp_combo")
    if not isinstance(combo, str):
        return None
    platform, gpu, screen = combo.split("|")
    c = {"platform": platform, "gpu": gpu, "screen": screen}
    for flag in FLAGS[:-1]:
        value = row.get(flag)
        c[flag] = 0 if value is None or pd.isna(value) else int(value)
    c["input_platform_mismatch"] = input_mismatch(platform, row.get("mouse_moves"),
                                                  row.get("touches"))
    return c


class AnomalyModel:
    """Smoothed frequency tables of verified-human device claims."""

    def __init__(self, meta):
        self.meta = meta
        self.threshold = meta["threshold"]
        self.n = meta["n"]
        self.platform = meta["platform"]
        self.gpu = meta["gpu"]
        self.screen = meta["screen"]
        self.flags = meta["flags"]          # flag -> number of humans with it set

    @classmethod
    def fit(cls, rows, budget=FPR_BUDGET):
        n, platform, gpu, screen = 0, Counter(), {}, {}
        flags = dict.fromkeys(FLAGS, 0)
        for _, row in rows.iterrows():
            c = claims(row)
            if c is None:
                continue
            n += 1
            platform[c["platform"]] += 1
            gpu.setdefault(c["platform"], Counter())[c["gpu"]] += 1
            screen.setdefault(c["platform"], Counter())[c["screen"]] += 1
            for flag in FLAGS:
                flags[flag] += c[flag]
        return cls({"n": n, "platform": dict(platform),
                    "gpu": {k: dict(v) for k, v in gpu.items()},
                    "screen": {k: dict(v) for k, v in screen.items()},
                    "flags": flags, "threshold": 0.0, "fpr_budget": budget})

    @staticmethod
    def _nll(count, total, vocab):
        """-log of an add-one smoothed probability (one extra slot for 'never seen')."""
        return -math.log((count + 1) / (total + vocab + 1))

    def terms(self, c):
        """Per-claim surprise, in nats. Larger = less like a verified human."""
        t = {"platform": self._nll(self.platform.get(c["platform"], 0), self.n, len(self.platform))}
        if c["gpu"] not in KNOWN_BENIGN_GPUS:
            for name, table in (("gpu", self.gpu), ("screen", self.screen)):
                seen = table.get(c["platform"], {})
                t[name] = self._nll(seen.get(c[name], 0), sum(seen.values()), len(seen))
        for flag in FLAGS:
            p_set = (self.flags[flag] + 1) / (self.n + 2)
            t[flag] = -math.log(p_set if c[flag] else 1 - p_set)
        return t

    def score_row(self, row):
        c = claims(row)
        return 0.0 if c is None else sum(self.terms(c).values())  # no JS: the supervised model's job

    def score(self, df):
        return np.array([self.score_row(row) for _, row in df.iterrows()])

    def save(self):
        with open(os.path.join(ARTIFACTS, "anomaly_v3.json"), "w") as fh:
            json.dump(self.meta, fh, indent=2)

    @classmethod
    def load(cls):
        with open(os.path.join(ARTIFACTS, "anomaly_v3.json")) as fh:
            return cls(json.load(fh))


def fit(df, budget):
    """Fit on the oldest 70% of verified humans; threshold on the newest 30%."""
    humans = df[df["label"] == 0].sort_values("ts")
    cut = int(len(humans) * 0.7)
    train, hold = humans.iloc[:cut], humans.iloc[cut:]
    model = AnomalyModel.fit(train, budget)
    hold_scores = model.score(hold)
    t = float(np.quantile(hold_scores, 1 - budget, method="higher")) + 1e-6
    model.meta["threshold"] = model.threshold = t
    return model, hold_scores


def main():
    parser = argparse.ArgumentParser(description="Fit the human-only anomaly detector.")
    parser.add_argument("--fpr-budget", type=float, default=FPR_BUDGET)
    parser.add_argument("--audit", action="store_true",
                        help="lab only: flag rate per true cohort on all recent checkouts")
    args = parser.parse_args()

    engine = make_engine()
    with engine.connect() as conn:
        df = build_dataset(conn, with_cohort=False)
        accounts = pd.read_sql("SELECT * FROM accounts", conn)
    if df.empty:
        sys.exit("No checkouts yet. Run tools/simulate.py first.")
    df["label"] = weak_labels(df, accounts)

    model, hold_scores = fit(df, args.fpr_budget)
    os.makedirs(ARTIFACTS, exist_ok=True)
    model.save()
    print(f"=== Anomaly model: device-claim likelihood on {model.n} verified-human sessions ===")
    print(f"  threshold {model.threshold:.2f} nats = top {args.fpr_budget:.0%} of "
          f"{len(hold_scores)} held-out verified humans")
    print("  saved artifacts/anomaly_v3.json")

    df["anomaly"] = model.score(df)
    worst = df.sort_values("anomaly", ascending=False).iloc[0]
    print(f"\n  most surprising session: {worst['fp_combo']}")
    for name, v in sorted(model.terms(claims(worst)).items(), key=lambda kv: -kv[1])[:4]:
        print(f"    {v:5.2f}  {name}")

    if args.audit:
        truth = load_truth()
        if truth.empty:
            return
        t = df.merge(truth, on="sid")
        t["who"] = np.where(t["is_bot"] == True, "bot:", "human:") + t["cohort"]  # noqa: E712
        print("\n  flag rate per TRUE cohort (lab-only view):")
        for who, g in t.groupby("who"):
            flagged = (g["anomaly"] >= model.threshold).mean()
            print(f"    {who:<26} {flagged:>5.0%}  of {len(g)}")


if __name__ == "__main__":
    main()
