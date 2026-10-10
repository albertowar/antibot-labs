"""
Chapter 7 — Analyst triage: label fingerprint clusters (Round 2, Section 7.3)

Model v1 let the humanized bot through, and nobody hit a honeypot, so
there is no bot label to retrain on. This is where production teams spend
analyst time: look at the POPULATION, find structure no human population
has, and label it by hand.

This tool groups checkout sessions by exact fingerprint and shows the
clusters that are both big and spread across many networks:

  sessions >= --min-sessions   one device configuration, many sessions
  /24s     >= --min-fanout     ...arriving from many unrelated networks

Real people collide too: identical iPhones on the same carrier share a
fingerprint, but they share a CGNAT /24 as well, so their fan-out stays low.
Clusters that contain verified customers are shown but NOT labeled:
a human label beats a cluster heuristic.

Labels go to data/manual_labels.jsonl (label 1 = bot) and are picked up by
`python defenses/train.py --round 2`.

Run:
    python tools/label_cluster.py            # show clusters, ask before labeling
    python tools/label_cluster.py --yes      # label without asking (checkpoint catch-up)
"""

import argparse
import json
import os
import sys
import time

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "defenses"))

from labels import LOYAL_MIN_AGE_DAYS, LOYAL_MIN_ORDERS, MANUAL_FILE  # noqa: E402
from netinfo import ip24, lookup  # noqa: E402
from store import make_engine  # noqa: E402


def clusters(conn, min_sessions, min_fanout):
    fps = pd.read_sql("SELECT sid, fp_hash, ip, payload FROM telemetry WHERE kind = 'fp'", conn)
    orders = pd.read_sql("SELECT DISTINCT sid FROM orders", conn)
    logins = pd.read_sql("SELECT l.sid, a.orders, a.age_days FROM logins l "
                         "JOIN accounts a ON a.account = l.account", conn)
    verified = set(logins.loc[(logins["orders"] >= LOYAL_MIN_ORDERS)
                              & (logins["age_days"] >= LOYAL_MIN_AGE_DAYS), "sid"])
    fps = fps[fps["sid"].isin(orders["sid"])].drop_duplicates("sid")
    fps["ip24"] = fps["ip"].map(ip24)
    rows = []
    for fp_hash, g in fps.groupby("fp_hash"):
        if len(g) < min_sessions:
            continue
        fp = json.loads(g["payload"].iloc[0])
        rows.append({
            "fp_hash": fp_hash[:10], "sessions": len(g), "ip24s": g["ip24"].nunique(),
            "asn": "/".join(sorted({lookup(ip)["asn_type"] for ip in g["ip"]})),
            "verified": int(g["sid"].isin(verified).sum()),
            "device": f"{fp.get('platform')} · {str(fp.get('gpu'))[:28]} · {fp.get('tz')}",
            "flag": len(g) >= min_sessions and g["ip24"].nunique() >= min_fanout,
            "sids": list(g["sid"]),
        })
    return pd.DataFrame(rows).sort_values("sessions", ascending=False) if rows else pd.DataFrame()


def main():
    parser = argparse.ArgumentParser(description="Find and label fingerprint clusters.")
    parser.add_argument("--min-sessions", type=int, default=10)
    parser.add_argument("--min-fanout", type=int, default=8)
    parser.add_argument("--yes", action="store_true", help="label flagged clusters without asking")
    args = parser.parse_args()

    with make_engine().connect() as conn:
        df = clusters(conn, args.min_sessions, args.min_fanout)
    if df.empty:
        print("No fingerprint shared by enough sessions.")
        return
    pd.set_option("display.width", 200)
    print(df.drop(columns=["sids"]).to_string(index=False))

    to_label = df[df["flag"] & (df["verified"] == 0)]
    skipped = df[df["flag"] & (df["verified"] > 0)]
    for row in skipped.itertuples():
        print(f"\n  ⚠️  {row.fp_hash}: contains {row.verified} verified customers, not labeling")
    if to_label.empty:
        print("\nNothing to label.")
        return
    n = sum(len(s) for s in to_label["sids"])
    print(f"\nLabel {len(to_label)} clusters ({n} sessions) as bot?", end=" ")
    if not args.yes and input("[y/N] ").strip().lower() != "y":
        print("Skipped.")
        return
    os.makedirs(os.path.dirname(MANUAL_FILE), exist_ok=True)
    with open(MANUAL_FILE, "a") as fh:
        for row in to_label.itertuples():
            for sid in row.sids:
                fh.write(json.dumps({"sid": sid, "label": 1, "by": "label_cluster",
                                     "cluster": row.fp_hash, "at": time.time()}) + "\n")
    print(f"{'yes' if args.yes else ''}\n  wrote {n} labels to data/manual_labels.jsonl")


if __name__ == "__main__":
    main()
