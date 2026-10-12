"""
Chapter 7 — Weak labels: where "bot" and "human" come from (Section 7.2)

Nobody hands you a labeled dataset. You assemble one from signals that are
high-precision but low-coverage:

  bot    = the session hit a honeypot (hidden link or robots-disallowed API, W1 Ch8)
  human  = the session logged into a long-standing account
           (>= 3 past orders, account older than 90 days)
  manual = analyst decisions in data/manual_labels.jsonl (Round 2:
           tools/label_cluster.py writes them). Manual labels win.
  everything else is UNLABELED and is left out of training.

Bias you are signing up for:
  - Bot labels only cover bots dumb enough to touch a honeypot. The model
    learns "what honeypot-hitting bots look like", not "what bots look like".
  - Human labels only cover loyal, logged-in customers. Privacy-browser and
    VPN users rarely log in, so the model barely sees them, and your FPR
    estimate is measured on the users least likely to be false positives.
  - Account takeover poisons the human label: a stuffed credential (W2 Ch6)
    turns a bot session into a "loyal customer".

`--audit` compares the weak labels with the simulator's ground truth. That
file only exists in the lab. Use it to see the bias, never to train.

Run:
    python defenses/labels.py --audit
"""

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))

from store import make_engine  # noqa: E402

LAB_DIR = os.path.join(os.path.dirname(__file__), "..")
MANUAL_FILE = os.path.join(LAB_DIR, "data", "manual_labels.jsonl")
TRUTH_FILE = os.path.join(LAB_DIR, "data", "truth.jsonl")

LOYAL_MIN_ORDERS = 3
LOYAL_MIN_AGE_DAYS = 90


def load_jsonl(path):
    if not os.path.exists(path):
        return pd.DataFrame()
    with open(path) as fh:
        return pd.DataFrame([json.loads(line) for line in fh if line.strip()])


def weak_labels(df, accounts, manual=True):
    """Return a Series: 1 = bot, 0 = human, NaN = unlabeled."""
    loyal = set(accounts.loc[(accounts["orders"] >= LOYAL_MIN_ORDERS)
                             & (accounts["age_days"] >= LOYAL_MIN_AGE_DAYS), "account"])
    label = pd.Series(np.nan, index=df.index)
    label[df["account"].isin(loyal)] = 0
    label[df["honeypot_hits"] > 0] = 1          # a honeypot hit beats a login
    analyst = load_jsonl(MANUAL_FILE) if manual else pd.DataFrame()
    if not analyst.empty:
        latest = analyst.drop_duplicates("sid", keep="last").set_index("sid")["label"]
        hit = df["sid"].isin(latest.index)
        label[hit] = df.loc[hit, "sid"].map(latest).astype(float)
    return label


def load_truth():
    truth = load_jsonl(TRUTH_FILE)
    return truth.drop_duplicates("sid", keep="last") if not truth.empty else truth


def audit(df, label):
    truth = load_truth()
    if truth.empty:
        print("No data/truth.jsonl yet: run tools/simulate.py first.")
        return
    t = df[["sid"]].assign(label=label).merge(truth, on="sid", how="left")
    t["who"] = np.where(t["is_bot"] == True, "bot:" + t["cohort"], "human:" + t["cohort"])  # noqa: E712
    rows = []
    for who, g in t.groupby("who"):
        rows.append({"who": who, "sessions": len(g),
                     "labeled bot": int((g["label"] == 1).sum()),
                     "labeled human": int((g["label"] == 0).sum()),
                     "unlabeled": int(g["label"].isna().sum())})
    print(pd.DataFrame(rows).to_string(index=False))
    lab = t[t["label"].notna()]
    wrong = int(((lab["label"] == 1) != (lab["is_bot"] == True)).sum())  # noqa: E712
    bots = t[t["is_bot"] == True]  # noqa: E712
    print(f"\nLabeled: {len(lab)}/{len(t)} sessions ({len(lab) / max(len(t), 1):.0%}).  "
          f"Wrong labels: {wrong}.  Bot coverage: "
          f"{(bots['label'] == 1).mean():.0%} of real bots carry a bot label.")


def main():
    parser = argparse.ArgumentParser(description="Weak labels and their audit.")
    parser.add_argument("--audit", action="store_true", help="compare with lab ground truth")
    args = parser.parse_args()

    from features import build_dataset
    engine = make_engine()
    with engine.connect() as conn:
        df = build_dataset(conn, with_cohort=False)
        accounts = pd.read_sql("SELECT * FROM accounts", conn)
    if df.empty:
        print("No checkouts yet. Run tools/simulate.py first.")
        return
    label = weak_labels(df, accounts)
    print(f"{len(df)} checkout sessions: {int((label == 1).sum())} labeled bot, "
          f"{int((label == 0).sum())} labeled human, {int(label.isna().sum())} unlabeled\n")
    if args.audit:
        audit(df, label)


if __name__ == "__main__":
    main()
