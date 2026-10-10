"""Cross-scenario scoreboard — the final debrief view.

Reads the decision log and, for each round that has traffic, shows how the store
split bots vs. humans across allow / challenge / block, the top reasons, and the
median scoring cost. For Round 5 it also splits GIVT from SIVT by the reason tag.
Run it after the last round, or any time, to see where the signal came from.

    python tools/scoreboard.py
    python tools/scoreboard.py --round 5
"""

from __future__ import annotations

import argparse
import collections
import os
import statistics
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "attacks"))
from _common import BASE_URL, require_local  # noqa: E402

NAMES = {1: "Credential stuffing", 2: "Scalping", 3: "Scraping",
         4: "Fake accounts", 5: "Click fraud"}


def group(rows, is_bot):
    sel = [r for r in rows if (r["actor"] in ("bot", "bot2")) == is_bot]
    t = collections.Counter(r["outcome"] for r in sel)
    return len(sel), t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, choices=[1, 2, 3, 4, 5], default=None)
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    require_local(a.url)
    rows = requests.get(f"{a.url}/lab/decisions", timeout=5).json()
    if not rows:
        print("No decisions recorded yet. Run a round's attack + checkpoint first.")
        return 0

    by_round = collections.defaultdict(list)
    for r in rows:
        by_round[r["round"]].append(r)
    rounds = [a.round] if a.round else sorted(by_round)

    print(f"=== Scoreboard ({len(rows)} decisions) ===")
    for rd in rounds:
        rr = by_round.get(rd, [])
        if not rr:
            continue
        nb, bt = group(rr, True)
        nh, ht = group(rr, False)
        lat = [r["latency_ms"] for r in rr if r["latency_ms"]]
        print(f"\n[{rd}] {NAMES[rd]}  ({len(rr)} decisions)")
        print(f"   bots   ({nb:4d}): " + "  ".join(f"{k}={v}" for k, v in sorted(bt.items())))
        print(f"   humans ({nh:4d}): " + "  ".join(f"{k}={v}" for k, v in sorted(ht.items())))
        if lat:
            print(f"   median scoring cost: {statistics.median(lat):.3f} ms")
        reasons = collections.Counter(r["reason"].split(" | ")[0] for r in rr
                                      if r["outcome"] == "block")
        if reasons:
            top = "  ".join(f"{why}×{n}" for why, n in reasons.most_common(3))
            print(f"   top block reasons: {top}")
        if rd == 5:
            tiers = collections.Counter(
                ("givt" if r["reason"].startswith("givt") else
                 "sivt" if r["reason"].startswith("sivt") else "other")
                for r in rr if r["outcome"] == "block")
            print(f"   IVT split: GIVT={tiers.get('givt',0)}  SIVT={tiers.get('sivt',0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
