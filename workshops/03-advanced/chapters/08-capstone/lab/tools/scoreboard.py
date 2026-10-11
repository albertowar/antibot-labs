"""
Chapter 9 — Scoreboard (Section 9.7, final debrief)

Reads the decisions table and prints the capstone scoreboard: for each
action, how the store split traffic across allow / challenge / block, the
top reasons, and the median scoring cost. Run it after a round, or at the
end, to review where points came from and which layer did the work.

Run:
    python tools/scoreboard.py
    python tools/scoreboard.py --action buy
"""

import argparse
import collections
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import admin, ensure_local  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=["buy", "login", "register", "request"], default=None)
    parser.add_argument("--limit", type=int, default=100000)
    args = parser.parse_args()
    ensure_local()
    query = f"/admin/decisions?limit={args.limit}" + (f"&action={args.action}" if args.action else "")
    rows = admin("GET", query)
    if not rows:
        print("No decisions recorded yet. Run a round first.")
        return 0

    by_action = collections.defaultdict(list)
    for r in rows:
        by_action[r["action"]].append(r)

    print(f"=== Scoreboard ({len(rows)} decisions, DEFENSE_LEVEL={rows[0]['level']}) ===\n")
    for action, group in sorted(by_action.items()):
        outcomes = collections.Counter(r["outcome"] for r in group)
        reasons = collections.Counter(reason for r in group for reason in r["reasons"])
        timings = [r["score_ms"] for r in group if r["score_ms"] is not None]
        print(f"{action}  ({len(group)})")
        print("   " + "  ".join(f"{k}={v}" for k, v in sorted(outcomes.items())))
        for reason, n in reasons.most_common(4):
            print(f"     {n:>4}×  {reason}")
        if timings:
            print(f"     cost: median {statistics.median(timings):.1f} ms")
        print()
    return 0


if __name__ == '__main__':
    sys.exit(main())
