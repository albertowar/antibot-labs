"""
W4 Ch4 — Scoreboard: what the store did, to whom

Reads /admin/decisions and prints, per X-Lab-Actor, the allow / challenge /
block split for checkouts, the principal the store assigned, the top reasons,
and the median scoring time. The actor label is ground truth for measurement
only; no defence reads it.

Run (store running):
    python tools/scoreboard.py
    python tools/scoreboard.py --since 0 --action checkout
"""

import argparse
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from lab import decisions  # noqa: E402

ORDER = ["allow", "challenge", "block", "deny", "error"]


def tally(rows):
    by = {}
    for d in rows:
        actor = d.get("actor") or "unknown"
        row = by.setdefault(actor, {"n": 0, "principals": {}, "outcomes": {}, "reasons": {}, "ms": [], "w2": []})
        row["n"] += 1
        row["outcomes"][d["outcome"]] = row["outcomes"].get(d["outcome"], 0) + 1
        row["principals"][d["principal"]] = row["principals"].get(d["principal"], 0) + 1
        for r in d.get("reasons", []):
            row["reasons"][r] = row["reasons"].get(r, 0) + 1
        if d.get("score_ms") is not None:
            row["ms"].append(d["score_ms"])
        w2 = (d.get("shadow") or {}).get("W2", {})
        if w2:
            row["w2"].append(w2.get("points", 0))
    return by


def print_board(rows, action="checkout"):
    checkout = [d for d in rows if d["action"] == action]
    by = tally(checkout)
    if not by:
        print(f"No {action} decisions yet.")
        return
    print(f"=== {action} decisions by actor ({len(checkout)} total) ===")
    for actor in sorted(by):
        row = by[actor]
        outs = " ".join(f"{k}={row['outcomes'][k]}" for k in ORDER if k in row["outcomes"])
        principals = ",".join(f"{k}:{v}" for k, v in row["principals"].items())
        w2 = f", W2-shadow median {statistics.median(row['w2']):.0f}" if row["w2"] else ""
        ms = f", score median {statistics.median(row['ms']):.1f} ms" if row["ms"] else ""
        print(f"  {actor:<20} n={row['n']:<3} [{principals}]  {outs}{w2}{ms}")
        for reason, n in sorted(row["reasons"].items(), key=lambda kv: -kv[1])[:2]:
            print(f"       - ({n}x) {reason[:110]}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--since", type=int, default=0)
    parser.add_argument("--action", default="checkout")
    args = parser.parse_args()
    print_board(decisions(since_id=args.since), args.action)
