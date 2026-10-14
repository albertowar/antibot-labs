"""
Analyst triage: label fingerprint clusters (Round 2)

Model v1 let the humanized bot through, and nobody hit a honeypot, so there is no bot label to
retrain on. This is where production teams spend analyst time: look at the POPULATION, find
structure no human population has, and label it by hand.

This tool groups purchase attempts by exact fingerprint and shows the clusters that are both big and
spread across many networks:

  sessions >= --min-sessions   one device configuration, many sessions
  addresses >= --min-fanout    ...arriving from many unrelated source addresses

Real people collide too: identical iPhones on the same carrier share a fingerprint, but they share a
CGNAT address as well, so their fan-out stays low. Clusters that contain verified customers are
shown but NOT labeled: a human label beats a cluster heuristic.

It first pulls the store's live log (whatever attack traffic you ran since the last pull) into
data/history/. Labels go to data/history/manual_labels.jsonl (label 1 = bot) and are picked up by
`python -m defenses.train --round 2`.

    python tools/label_cluster.py            # show clusters, ask before labeling
    python tools/label_cluster.py --yes      # label without asking (checkpoint catch-up)
"""

import argparse
import json
import os
import sys
import time

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import analyst  # noqa: E402
import labclient  # noqa: E402
from defenses import history, netinfo  # noqa: E402
from defenses.labels import loyal_accounts  # noqa: E402


def clusters(hist, min_sessions, min_fanout):
    buys = {e["sid"] for e in hist["events"] if e["method"] == "POST" and e["path"].startswith("/drop/")}
    verified = {sid for sid, acct in hist["logins"].items() if acct in loyal_accounts(hist["accounts"])}
    seen, by_fp = set(), {}
    for t in hist["telemetry"]:
        if t["kind"] != "fp" or t["sid"] not in buys or t["sid"] in seen:
            continue
        seen.add(t["sid"])
        by_fp.setdefault(t["fp_hash"], []).append(t)
    rows = []
    for fp_hash, g in by_fp.items():
        if len(g) < min_sessions:
            continue
        sids = [t["sid"] for t in g]
        ips = {t["ip"] for t in g}
        fp = g[0]["payload"]
        rows.append({
            "fp_hash": fp_hash[:10], "sessions": len(g), "addresses": len(ips),
            "asn": "/".join(sorted({netinfo.lookup(ip)["asn_type"] for ip in ips})),
            "verified": len(set(sids) & verified),
            "device": f"{fp.get('platform')} | {str(fp.get('gpu'))[:28]} | {fp.get('tz')}",
            "flag": len(ips) >= min_fanout, "sids": sids,
        })
    return pd.DataFrame(rows).sort_values("sessions", ascending=False) if rows else pd.DataFrame()


def main():
    parser = argparse.ArgumentParser(description="Find and label fingerprint clusters.")
    parser.add_argument("--min-sessions", type=int, default=10)
    parser.add_argument("--min-fanout", type=int, default=8)
    parser.add_argument("--yes", action="store_true", help="label flagged clusters without asking")
    args = parser.parse_args()

    labclient.wait_for_store()
    print(f"pulled {analyst.pull()} new sessions from the store's log into data/history/")
    df = clusters(history.load(), args.min_sessions, args.min_fanout)
    if df.empty:
        print("No fingerprint shared by enough sessions.")
        return
    pd.set_option("display.width", 200)
    print(df.drop(columns=["sids"]).to_string(index=False))

    to_label = df[df["flag"] & (df["verified"] == 0)]
    skipped = df[df["flag"] & (df["verified"] > 0)]
    for row in skipped.itertuples():
        print(f"\n  {row.fp_hash}: contains {row.verified} verified customers, not labeling")
    if to_label.empty:
        print("\nNothing to label.")
        return
    n = sum(len(s) for s in to_label["sids"])
    print(f"\nLabel {len(to_label)} clusters ({n} sessions) as bot?", end=" ")
    if not args.yes and input("[y/N] ").strip().lower() != "y":
        print("Skipped.")
        return
    os.makedirs(os.path.dirname(history.MANUAL), exist_ok=True)
    with open(history.MANUAL, "a") as fh:
        for row in to_label.itertuples():
            for sid in row.sids:
                fh.write(json.dumps({"sid": sid, "label": 1, "by": "label_cluster",
                                     "cluster": row.fp_hash, "at": time.time()}) + "\n")
    print(f"{'yes' if args.yes else ''}\n  wrote {n} labels to data/history/manual_labels.jsonl")


if __name__ == "__main__":
    main()
