"""
Audit against the answer key (lab only)

The simulator knows who every session really was (data/history/truth.jsonl, written from the decision
log's actor labels). Production has no such file. This tool uses it to show the BIAS in what you
trained on, and nothing here may ever feed a model.

    python tools/audit.py labels      # who carries a label, and is it right? (Round 0)
    python tools/audit.py anomaly     # flag rate of the anomaly detector per TRUE cohort 

The first prints, per true cohort: sessions, labeled bot, labeled human, unlabeled. The second fits
the detector on verified humans, as `python -m defenses.anomaly` does, and prints how often each true
cohort would be flagged at its threshold.
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: F401,E402  (puts the lab root on sys.path; runs the labnet guard)
from defenses import anomaly, history  # noqa: E402
from defenses.features import build_dataset  # noqa: E402
from defenses.labels import weak_labels  # noqa: E402


def with_truth(df):
    truth = history.load_truth()
    df = df.assign(actor=df["sid"].map(truth))
    df["who"] = df["actor"].map(lambda a: a.rsplit(":", 1)[0] if isinstance(a, str) else "?")
    return df


def audit_labels():
    hist = history.load()
    df = build_dataset(hist, with_cohort=False)
    if df.empty:
        sys.exit("No purchase attempts in the history yet. Run: python tools/simulate.py")
    df["label"] = weak_labels(df, hist["accounts"], manual=False)
    print(f"{len(df)} purchase attempts: {int((df['label'] == 1).sum())} labeled bot, "
          f"{int((df['label'] == 0).sum())} labeled human, {int(df['label'].isna().sum())} unlabeled\n")
    t = with_truth(df)
    rows = [{"who": who, "sessions": len(g), "labeled bot": int((g["label"] == 1).sum()),
             "labeled human": int((g["label"] == 0).sum()), "unlabeled": int(g["label"].isna().sum())}
            for who, g in t.groupby("who")]
    print(pd.DataFrame(rows).to_string(index=False))
    lab = t[t["label"].notna()]
    is_bot = lab["actor"].str.startswith("bot:")
    wrong = int(((lab["label"] == 1) != is_bot).sum())
    bots = t[t["actor"].str.startswith("bot:", na=False)]
    print(f"\nLabeled: {len(lab)}/{len(t)} sessions ({len(lab) / max(len(t), 1):.0%}).  "
          f"Wrong labels: {wrong}.  Bot coverage: {(bots['label'] == 1).mean():.0%} of real bots carry a bot label.")
    return {"wrong": wrong, "bot_coverage": float((bots["label"] == 1).mean()), "labeled": len(lab), "sessions": len(t)}


def audit_anomaly():
    df = anomaly.labeled_dataset()
    model, _ = anomaly.fit(df, anomaly.FPR_BUDGET)
    df["anomaly"] = model.score(df)
    t = with_truth(df)
    print(f"flag rate per TRUE cohort at threshold {model.threshold:.2f} nats (lab-only view):")
    out = {}
    for who, g in t.groupby("who"):
        out[who] = float((g["anomaly"] >= model.threshold).mean())
        print(f"  {who:<28} {out[who]:>5.0%}  of {len(g)}")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=("labels", "anomaly"))
    args = ap.parse_args()
    import analyst                      # pull the traffic you sent since the last pull (the checkpoint does not)
    labclient.wait_for_store()
    analyst.pull()
    audit_labels() if args.what == "labels" else audit_anomaly()
