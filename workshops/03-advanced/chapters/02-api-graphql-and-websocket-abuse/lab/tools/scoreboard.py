"""Scoreboard — read the decision log and show both sides of the arms race.

Reads /admin/decisions and summarises, per surface and action, how traffic was
scored and at what cost. ``actor`` is lab ground truth (set by the attack and
legit clients), so we can print blocked bots next to blocked real users — the one
comparison that tells you whether a defense is worth running.

    python tools/scoreboard.py
    python tools/scoreboard.py --surface graphql
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
from collections import Counter, defaultdict

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import require_local, target  # noqa: E402

BASE_URL = target("DEMO_URL", "http://127.0.0.1:5000")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE_URL, type=require_local)
    ap.add_argument("--surface")
    ap.add_argument("--limit", type=int, default=2000)
    args = ap.parse_args()

    rows = httpx.get(f"{args.base}/admin/decisions", params={"limit": args.limit}, timeout=10).json()
    if args.surface:
        rows = [r for r in rows if r["surface"] == args.surface]
    if not rows:
        print("no decisions logged yet")
        return

    by_key = defaultdict(list)
    for r in rows:
        by_key[(r["surface"], r["action"])].append(r)

    print(f"{'surface/action':28} {'allow':>6} {'chal':>5} {'block':>6} {'p50 ms':>7}  top reason")
    for (surface, action), items in sorted(by_key.items()):
        outc = Counter(i["outcome"] for i in items)
        costs = [i["cost_ms"] for i in items if i["cost_ms"]]
        p50 = round(statistics.median(costs), 2) if costs else 0.0
        reasons = Counter(rr for i in items for rr in i["reasons"] if not rr.startswith("messages"))
        top = reasons.most_common(1)[0][0] if reasons else ""
        print(f"{surface + '/' + action:28} {outc.get('allow', 0):>6} {outc.get('challenge', 0):>5} "
              f"{outc.get('block', 0):>6} {p50:>7}  {top[:42]}")

    # Bot vs legit, the headline number.
    bots = [r for r in rows if r["actor"].startswith("bot")]
    legit = [r for r in rows if r["actor"].startswith("legit")]
    bot_blocked = sum(1 for r in bots if r["outcome"] in ("block", "challenge"))
    legit_blocked = sum(1 for r in legit if r["outcome"] in ("block", "challenge"))
    print(f"\nbot requests stopped: {bot_blocked}/{len(bots)}    "
          f"legit requests caught (false positives): {legit_blocked}/{len(legit)}")


if __name__ == "__main__":
    main()
