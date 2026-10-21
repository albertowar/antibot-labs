"""
Round 3 reference: the takeovers nobody shares anything with.

The low-and-slow operator uses one fresh browser profile per victim, a residential
address in the victim's own city, a mainstream TLS stack, and makes no high-risk
change in the first half hour. Nothing links the victims to each other or to
anything we already caught. What is left is the account's own past: this person
never logged in at that hour, never from that timezone, never with that locale,
never ordered that much, and all of it changed in the same week.

Two models, and what each one is for:

  1. Unsupervised, per account, against its own baseline. For each weekly as-of
     point, features from the last 14 days are compared with the account's
     behaviour before that (window_features, which refuses to look ahead). An
     IsolationForest over the deviation features scores every (account, week);
     the account's score is its worst week. Accounts with fewer than 8 baseline
     events are skipped: there is nothing to deviate from, and a model that scores
     them is scoring noise.

  2. Supervised, on the labels we have. Rounds 1 and 2 are the positives; a
     gradient-boosted classifier on the same features learns what *those*
     takeovers look like. It is good at them and weak at the low-and-slow ones,
     which is the point of showing it: a model trained on the detections you
     already have finds more of what you already find.

The deliverable is a review queue, not a verdict: the top 100 by anomaly score
that Round 2 did not already contain. The scorer reports precision at 25/50/100
because that is the number an analyst can actually open.

Run:
    python solutions/round3_anomaly.py          # needs solutions/checkpoints/suspects_r2.csv
"""

import argparse
import os
import sys
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB, "tools"))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest  # noqa: E402
from atolab import dedupe, load_events, save_suspects, score_now, window_features  # noqa: E402

W = 14      # feature window in days: wide enough to hold an operator's first and second visit
DEVIATION = ["hour_delta", f"w{W}_tz_shift", f"w{W}_lang_shift", f"w{W}_share_base_device", f"w{W}_share_base_asn", f"w{W}_share_base_country", f"w{W}_new_ids",
             f"w{W}_alerts_off", "amount_ratio", f"w{W}_med", f"w{W}_high", f"w{W}_logins", f"w{W}_resume_share", "days_since_base", f"w{W}_devices", f"w{W}_asns"]
WEEKS = [f"2026-{m:02d}-{d:02d}" for m, d in [(11, 2), (11, 9), (11, 16), (11, 23), (11, 30), (12, 7), (12, 14), (12, 21), (12, 29)]]


def weekly_features(df):
    frames = []
    for as_of in WEEKS:
        X = window_features(df, as_of=as_of, windows=(W,))
        X = X[(X["base_events"].fillna(0) >= 8) & (X[f"w{W}_events"] > 0)].copy()
        X["as_of"] = as_of
        frames.append(X)
    F = pd.concat(frames)
    F["amount_ratio"] = np.log1p(F["amount_ratio"].fillna(1.0).clip(upper=50))
    F["days_since_base"] = np.log1p(F["days_since_base"].fillna(0))
    F["hour_delta"] = F["hour_delta"].fillna(0)
    return F


def run(df, prev, top_k=100, seed=2026):
    F = weekly_features(df)
    X = F[DEVIATION].fillna(0).to_numpy()
    iso = IsolationForest(n_estimators=300, contamination="auto", random_state=seed).fit(X)
    F["anomaly"] = -iso.score_samples(X)
    per_acc = F.groupby(level=0)["anomaly"].max().sort_values(ascending=False)
    known = set(prev["account_id"])
    # supervised, for contrast: learn Round 1+2's takeovers, see what it adds
    agg = F.groupby(level=0)[DEVIATION].max()
    y = agg.index.isin(known).astype(int)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        clf = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.05, random_state=seed).fit(agg.to_numpy(), y)
    agg["p_sup"] = clf.predict_proba(agg.to_numpy())[:, 1]
    sup_new = agg[~agg.index.isin(known)].sort_values("p_sup", ascending=False).head(top_k)
    queue = per_acc[~per_acc.index.isin(known)].head(top_k)
    print(f"{len(F)} (account, week) rows scored; {per_acc.size} accounts with a baseline; queue = top {top_k} new by anomaly")
    print(f"supervised model: top-{top_k} new accounts by P(takeover) kept aside as 'sup' (compare with --supervised)")
    return queue, sup_new


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prev", default=os.path.join(HERE, "checkpoints", "suspects_r2.csv"))
    ap.add_argument("--out", default=os.path.join(HERE, "checkpoints", "suspects_r3.csv"))
    ap.add_argument("--top", type=int, default=100)
    ap.add_argument("--supervised", action="store_true", help="submit the supervised model's queue instead of the anomaly queue")
    ap.add_argument("--no-score", action="store_true")
    args = ap.parse_args()
    prev = pd.read_csv(args.prev)
    df = dedupe(load_events())
    queue, sup = run(df, prev, top_k=args.top)
    chosen = sup["p_sup"] if args.supervised else queue
    out = pd.concat([pd.DataFrame({"account_id": prev["account_id"], "score": 10.0 + prev.get("score", pd.Series(0, index=prev.index)).fillna(0), "first_event_id": prev.get("first_event_id")}),
                     pd.DataFrame({"account_id": chosen.index, "score": chosen.to_numpy(), "first_event_id": None})]).drop_duplicates("account_id")
    save_suspects(out[["account_id"]], args.out, scores=out["score"], first_event=out["first_event_id"])
    if not args.no_score:
        score_now(args.out, "--prev", args.prev)


if __name__ == "__main__":
    main()
