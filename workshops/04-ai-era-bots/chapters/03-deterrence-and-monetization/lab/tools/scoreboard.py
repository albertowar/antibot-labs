"""Scoreboard — the debrief view.

Reads the decision log and, per defense level, shows how the store treated each
actor cohort (allow / block / maze / paywall / charged), the crawlers' catalogue
coverage, revenue booked, and the maze's cost. Run it any time; it never
resets anything.

    python tools/scoreboard.py
    python tools/scoreboard.py --level 3
"""

from __future__ import annotations

import argparse
import collections
import os
import statistics
import sys

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "attacks"))
from _common import BASE_URL, require_local  # noqa: E402

RUNG = {0: "no governance", 1: "policy published", 2: "policy enforced",
        3: "maze for the rest", 4: "pay-per-crawl"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", type=int, choices=[0, 1, 2, 3, 4], default=None)
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    require_local(a.url)
    rows = httpx.get(f"{a.url}/lab/decisions", timeout=10).json()
    stats = httpx.get(f"{a.url}/lab/stats", timeout=5).json()
    if not rows:
        print("No decisions recorded yet. Run a round's crawlers or checkpoint first.")
        return 0
    by_level = collections.defaultdict(list)
    for r in rows:
        by_level[r["level"]].append(r)
    print(f"=== Scoreboard ({len(rows)} decisions) ===")
    for lvl in ([a.level] if a.level is not None else sorted(by_level)):
        rr = by_level.get(lvl, [])
        if not rr:
            continue
        print(f"\n[L{lvl}] {RUNG[lvl]}  ({len(rr)} decisions)")
        for actor in ("human", "prefetch", "reader", "search", "bot"):
            sel = [r for r in rr if r["actor"] == actor]
            if not sel:
                continue
            t = collections.Counter(r["outcome"] for r in sel)
            line = "  ".join(f"{k}={v}" for k, v in sorted(t.items()))
            skus = set()
            for r in sel:
                if r["outcome"] in ("allow", "charged") and r["skus"]:
                    skus.update(r["skus"].split(","))
            extra = f"  coverage {len(skus) / 300:.0%}" if actor in ("bot", "search") else ""
            print(f"   {actor:9s} ({len(sel):4d}): {line}{extra}")
        lat = [r["latency_ms"] for r in rr if r["latency_ms"]]
        if lat:
            print(f"   median gate cost: {statistics.median(lat):.2f} ms")
        reasons = collections.Counter(r["reason"].split(":")[0] for r in rr if r["outcome"] == "block")
        if reasons:
            print("   top block reasons: " + "  ".join(f"{w}×{n}" for w, n in reasons.most_common(3)))
        viol = sum(1 for r in rr if "robots-violation" in r["reason"])
        if viol:
            print(f"   robots.txt violations logged: {viol}")
    if stats["ledger"]:
        print(f"\nrevenue booked: " + "  ".join(f"{k}=${v:.2f}" for k, v in stats["ledger"].items()))
    m = stats["maze"]
    if m["pages"]:
        print(f"maze cost: {m['pages']} pages, {m['gen_ms_total'] / m['pages']:.2f} ms/page, "
              f"{m['bytes'] / 1024:.0f} KB, cap hit {m['capped']}x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
