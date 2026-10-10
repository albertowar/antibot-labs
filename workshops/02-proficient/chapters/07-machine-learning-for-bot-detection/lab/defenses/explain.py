"""
Chapter 7 — Why did the model say that? Per-checkout explanations (Round 2, Section 7.3)

LightGBM computes exact TreeSHAP contributions itself:
`booster.predict(X, pred_contrib=True)` returns, for every row, one number
per feature plus a bias term. They add up to the model's raw score
(log-odds), so each number reads as "this feature pushed the score toward
bot (+) or human (-) by this much". No extra package needed.

Use it for:
  - triage: why did these checkouts get through? (--allowed)
  - false positives: why was this customer blocked? (--sid)
  - sanity: what does the model lean on overall? (--global)

What SHAP does NOT tell you: whether the feature is causal, whether the
attacker can change it cheaply, or what the model would do on data it has
never seen. It explains the model, not the world.

Run:
    python defenses/explain.py --model 1 --allowed 8
    python defenses/explain.py --model 2 --sid <sid>
    python defenses/explain.py --model 1 --global
"""

import argparse
import json
import os
import sys

import lightgbm as lgb
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))

from features import build_dataset  # noqa: E402
from scorer import ARTIFACTS  # noqa: E402
from store import make_engine  # noqa: E402


def load(version):
    base = os.path.join(ARTIFACTS, f"model_v{version}")
    with open(f"{base}.json") as fh:
        return lgb.Booster(model_file=f"{base}.txt"), json.load(fh)


def fmt_value(v):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "–"
    return f"{v:.2f}" if isinstance(v, float) and not float(v).is_integer() else f"{int(v)}"


def explain_rows(booster, meta, rows, top=4):
    X = rows[meta["features"]]
    contrib = booster.predict(X, pred_contrib=True)
    p = booster.predict(X)
    for i, (_, row) in enumerate(rows.iterrows()):
        c = pd.Series(contrib[i, :-1], index=meta["features"])
        order = c.abs().sort_values(ascending=False).index[:top]
        verdict = "BLOCK" if p[i] >= meta["threshold"] else "allow"
        print(f"\n  sid {row['sid'][:10]}  fp {str(row.get('fp_hash') or '–')[:8]}  "
              f"ip {row['ip']:<15} p_bot={p[i]:.3f} → {verdict}")
        for name in order:
            arrow = "→ bot  " if c[name] > 0 else "→ human"
            print(f"      {arrow} {c[name]:+6.2f}  {name} = {fmt_value(row[name])}")


def main():
    parser = argparse.ArgumentParser(description="Explain model decisions with TreeSHAP.")
    parser.add_argument("--model", type=int, choices=(1, 2), default=1)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--allowed", type=int, metavar="N", help="the N newest allowed checkouts")
    group.add_argument("--sid", help="one session")
    group.add_argument("--global", dest="global_", action="store_true",
                       help="mean |contribution| per feature")
    args = parser.parse_args()

    booster, meta = load(args.model)
    engine = make_engine()
    with engine.connect() as conn:
        df = build_dataset(conn, with_cohort=args.model >= 2)
        decisions = pd.read_sql("SELECT sid, decision FROM orders ORDER BY ts", conn)
    df = df.merge(decisions.drop_duplicates("sid", keep="last"), on="sid", how="left")

    if args.global_:
        contrib = booster.predict(df[meta["features"]], pred_contrib=True)[:, :-1]
        imp = pd.Series(np.abs(contrib).mean(axis=0), index=meta["features"])
        print(f"Model v{args.model}: mean |SHAP| over {len(df)} checkouts")
        for name, v in imp.sort_values(ascending=False).head(12).items():
            print(f"  {v:6.3f}  {'█' * int(v * 10):<30} {name}")
        return
    if args.sid:
        rows = df[df["sid"].str.startswith(args.sid)]
        if rows.empty:
            sys.exit(f"No checkout for sid {args.sid}")
    else:
        rows = df[df["decision"] == "allow"].sort_values("ts").tail(args.allowed)
    print(f"Model v{args.model} (threshold {meta['threshold']:.3f}). "
          f"Contributions are log-odds; + pushes toward bot.")
    explain_rows(booster, meta, rows)


if __name__ == "__main__":
    main()
