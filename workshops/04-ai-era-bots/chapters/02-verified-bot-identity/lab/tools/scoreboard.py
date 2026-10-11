"""Scoreboard: the decision log by identity, with both sides of the ledger.

    python tools/scoreboard.py

Reads /admin/decisions. `actor` is lab ground truth, so the table can show who was
*really* sending each request next to what the gate decided: impostors in the
verified lane are false negatives, genuine crawlers in the anonymous lane and
blocked humans are false positives, and `p50 ms` is what each decision cost.
"""

from __future__ import annotations

import argparse
import os
import statistics
from collections import Counter, defaultdict

import httpx

BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE_URL)
    ap.add_argument("--limit", type=int, default=5000)
    args = ap.parse_args()
    rows = httpx.get(f"{args.base}/admin/decisions", params={"limit": args.limit}, timeout=10).json()
    if not rows:
        print("no decisions logged yet")
        return
    by_actor = defaultdict(list)
    for r in rows:
        by_actor[r["actor"]].append(r)
    print(f"{'actor (ground truth)':26} {'claim':14} {'verified as':16} {'method':12} {'lane':9} {'ok':>4} {'429':>4} {'403':>4} {'p50 ms':>7}  top reason")
    for actor, items in sorted(by_actor.items()):
        st = Counter(i["status"] for i in items)
        claim = Counter(i["claim"] or "-" for i in items).most_common(1)[0][0]
        ident = Counter(i["identity"] or "-" for i in items).most_common(1)[0][0]
        method = Counter(i["method"] or "-" for i in items).most_common(1)[0][0]
        lane = Counter(i["lane"] for i in items).most_common(1)[0][0]
        p50 = statistics.median(i["cost_ms"] for i in items)
        top = Counter(rr for i in items for rr in i["reasons"]).most_common(1)
        print(f"{actor:26} {claim:14} {ident[:16]:16} {method:12} {lane:9} {st.get(200,0):>4} {st.get(429,0):>4} {st.get(403,0):>4} {p50:>7.2f}  {(top[0][0] if top else '')[:48]}")
    bots = [r for r in rows if r["actor"].startswith("bot")]
    crawlers = [r for r in rows if r["actor"].startswith("legit-crawler")]
    humans = [r for r in rows if r["actor"] == "legit-human"]
    print(f"\nimpostor requests in the verified lane: {sum(1 for r in bots if r['lane'] == 'verified')}/{len(bots)}    "
          f"genuine-crawler requests throttled: {sum(1 for r in crawlers if r['status'] != 200)}/{len(crawlers)}    "
          f"humans blocked: {sum(1 for r in humans if r['status'] != 200)}/{len(humans)}")


if __name__ == "__main__":
    main()
