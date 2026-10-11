"""Cross-round scoreboard — the final debrief view.

Reads the decision log and, for each round with traffic, shows how the store split
bots vs. humans across allow / challenge / block, the top block reasons, the
median scoring cost and the LLM tokens spent on each side. It also runs the toy
AI-text detector over every stored review and reports how often it flags *humans*
— the number that shows why "does this read like AI?" is not a bot signal.

    python tools/scoreboard.py
    python tools/scoreboard.py --round 4
"""

from __future__ import annotations

import argparse
import collections
import os
import statistics
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
sys.path.insert(0, LAB_DIR)
from attacks._common import BASE_URL, require_local  # noqa: E402

NAMES = {1: "Review farm", 2: "Challenge solver", 3: "LLM extraction", 4: "Prompt injection"}


def group(rows, is_bot):
    sel = [r for r in rows if (r["actor"] == "bot") == is_bot]
    return len(sel), collections.Counter(r["outcome"] for r in sel)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, choices=[1, 2, 3, 4], default=None)
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
        bot_tok = sum(r.get("tokens", 0) for r in rr if r["actor"] == "bot")
        print(f"\n[{rd}] {NAMES[rd]}  ({len(rr)} decisions)")
        print(f"   bots   ({nb:4d}): " + "  ".join(f"{k}={v}" for k, v in sorted(bt.items())))
        print(f"   humans ({nh:4d}): " + "  ".join(f"{k}={v}" for k, v in sorted(ht.items())))
        if lat:
            print(f"   median scoring cost: {statistics.median(lat):.3f} ms")
        if bot_tok:
            print(f"   LLM tokens the attacker spent: {bot_tok}")
        reasons = collections.Counter(r["reason"].split(" | ")[0] for r in rr if r["outcome"] == "block")
        if reasons:
            print("   top block reasons: " + "  ".join(f"{why}×{n}" for why, n in reasons.most_common(3)))

    # The AI-text-detector aside: how often does it flag humans vs bots?
    try:
        reviews = requests.get(f"{a.url}/lab/reviews", timeout=5).json()
    except Exception:
        reviews = []
    if reviews:
        human = [r for r in reviews if r["actor"] == "human"]
        bot = [r for r in reviews if r["actor"] == "bot"]
        hf = sum(r["generated_looking"] for r in human)
        bf = sum(r["generated_looking"] for r in bot)
        print(f"\n[aside] toy AI-text detector flagged {hf}/{len(human)} human reviews "
              f"and {bf}/{len(bot)} bot reviews as 'generated'.")
        print("        It fires on careful human prose and misses casual bot prose: "
              "a reason to score the account and the traffic, not the writing (W4 Ch6).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
