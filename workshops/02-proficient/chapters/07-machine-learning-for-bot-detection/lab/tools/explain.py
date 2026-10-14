"""
Why did the model say that? Per-purchase explanations (Round 2)

LightGBM computes exact TreeSHAP contributions itself: `booster.predict(X, pred_contrib=True)`
returns, for every row, one number per feature plus a bias term. They add up to the model's raw score
(log-odds), so each number reads as "this feature pushed the score toward bot (+) or human (-) by
this much". No extra package needed.

Use it for:
  - triage: why did these purchases get through? (--allowed)
  - false positives: why was this customer blocked? (--sid)
  - sanity: what does the model lean on overall? (--global)

What SHAP does NOT tell you: whether the feature is causal, whether the attacker can change it
cheaply, or what the model would do on data it has never seen. It explains the model, not the world.

It pulls the store's live log into data/history/ first (tools/analyst.py), so the traffic you just
sent is in it.

    python tools/explain.py --model 1 --allowed 4
    python tools/explain.py --model 2 --sid <sid>
    python tools/explain.py --model 1 --global
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import analyst  # noqa: E402
import labclient  # noqa: E402
from defenses import history, models  # noqa: E402
from defenses.features import build_dataset  # noqa: E402


def fmt_value(v):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "-"
    return f"{v:.2f}" if isinstance(v, float) and not float(v).is_integer() else f"{int(v)}"


def explain_rows(booster, meta, rows, top=4):
    X = rows[meta["features"]]
    contrib = booster.predict(X, pred_contrib=True)
    p = booster.predict(X)
    for i, (_, row) in enumerate(rows.iterrows()):
        c = pd.Series(contrib[i, :-1], index=meta["features"])
        order = c.abs().sort_values(ascending=False).index[:top]
        verdict = "BLOCK" if p[i] >= meta["threshold"] else "allow"
        print(f"\n  sid {row['sid'][:10]}  fp {str(row.get('fp_hash') or '-')[:8]}  "
              f"ip {row['ip']:<15} p_bot={p[i]:.3f} -> {verdict}")
        for name in order:
            arrow = "-> bot  " if c[name] > 0 else "-> human"
            print(f"      {arrow} {c[name]:+6.2f}  {name} = {fmt_value(row[name])}")


def main():
    parser = argparse.ArgumentParser(description="Explain model decisions with TreeSHAP.")
    parser.add_argument("--model", type=int, choices=(1, 2), default=1)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--allowed", type=int, metavar="N", help="the N newest purchases that went through")
    group.add_argument("--sid", help="one session (a prefix is enough)")
    group.add_argument("--global", dest="global_", action="store_true", help="mean |contribution| per feature")
    args = parser.parse_args()

    booster, meta = models.load_model(args.model)
    labclient.wait_for_store()
    analyst.pull()
    hist = history.load()
    df = build_dataset(hist, with_cohort=args.model >= 2)
    status = {}
    for e in hist["events"]:
        if e["method"] == "POST" and e["path"].startswith("/drop/"):
            status[e["sid"]] = e["status"]
    df["status"] = df["sid"].map(status)

    if args.global_:
        contrib = booster.predict(df[meta["features"]], pred_contrib=True)[:, :-1]
        imp = pd.Series(np.abs(contrib).mean(axis=0), index=meta["features"])
        print(f"Model v{args.model}: mean |SHAP| over {len(df)} purchase attempts")
        for name, v in imp.sort_values(ascending=False).head(12).items():
            print(f"  {v:6.3f}  {'#' * int(v * 10):<30} {name}")
        return
    if args.sid:
        rows = df[df["sid"].str.startswith(args.sid)]
        if rows.empty:
            sys.exit(f"No purchase attempt for sid {args.sid}")
    else:
        rows = df[df["status"].isin([200, 202])].sort_values("ts").tail(args.allowed)
    print(f"Model v{args.model} (threshold {meta['threshold']:.3f}). "
          f"Contributions are log-odds; + pushes toward bot.")
    explain_rows(booster, meta, rows)
    if args.allowed:
        # Per-session, every row says "human". Look at the population: which fingerprints repeat among ALL the purchases that got through?
        through = df[df["status"].isin([200, 202]) & df["fp_hash"].notna()]
        top = through.groupby("fp_hash").agg(sessions=("sid", "size"), addresses=("ip", "nunique")).sort_values("sessions", ascending=False).head(3)
        print(f"\n  fingerprints that repeat among the {len(through)} purchases that got through (the Round 2 question):")
        for fp_hash, r in top.iterrows():
            print(f"    fp {fp_hash[:8]}  {r['sessions']:>4} sessions from {r['addresses']:>3} addresses")


if __name__ == "__main__":
    main()
