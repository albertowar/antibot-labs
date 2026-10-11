"""Scoreboard: what the store decided, by who was really asking.

Reads the decision log (/lab/decisions) and groups it by the ground-truth actor the
traffic generators stamped: humans, legitimate non-browser clients and declared
crawlers on one side, attack scripts on the other. For each group it shows the
identity classes the store assigned, the actions it took, and the top reasons.

    python tools/scoreboard.py
    python tools/scoreboard.py --identity      # per identity class instead of per actor group
"""

from __future__ import annotations

import argparse
import collections
import os
import statistics
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "attacks"))
from _common import BASE_URL, require_local  # noqa: E402


def group_of(actor: str) -> str:
    if actor.startswith("human:"):
        return "humans"
    if actor.startswith("legit:verified") or actor == "legit:localsearchbot":
        return "declared crawlers"
    if actor.startswith("legit:"):
        return "non-browser legit"
    if actor.startswith("attack:"):
        return "attacks"
    return "you (browser)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=BASE_URL)
    ap.add_argument("--identity", action="store_true")
    a = ap.parse_args()
    require_local(a.url)
    rows = requests.get(f"{a.url}/lab/decisions", timeout=10).json()
    if not rows:
        print("No decisions yet. Run tools/traffic_mix.py or a checkpoint first.")
        return 0
    level = rows[-1]["level"]
    print(f"=== Scoreboard: {len(rows)} page decisions at DEFENSE_LEVEL={level} ===")
    key = (lambda r: r["identity"]) if a.identity else (lambda r: group_of(r["actor"]))
    by = collections.defaultdict(list)
    for r in rows:
        by[key(r)].append(r)
    for name in sorted(by):
        rr = by[name]
        actions = collections.Counter(r["action"] for r in rr)
        idents = collections.Counter(r["identity"] for r in rr)
        print(f"\n{name}  ({len(rr)} requests)")
        print("   actions:    " + "  ".join(f"{k}={v}" for k, v in sorted(actions.items())))
        print("   identities: " + "  ".join(f"{k}={v}" for k, v in idents.most_common()))
        reasons = collections.Counter(r["reason"].split(" | ")[0] for r in rr if r["action"] != "allow")
        if reasons:
            print("   reasons:    " + "  ".join(f"{why} x{n}" for why, n in reasons.most_common(3)))
    lat = [r["latency_ms"] for r in rows]
    print(f"\nidentification cost: median {statistics.median(lat):.2f} ms, max {max(lat):.2f} ms per page request")
    hurt = [r for r in rows if group_of(r["actor"]) in ("humans", "non-browser legit") and r["action"] in ("block", "challenge")]
    caught = [r for r in rows if group_of(r["actor"]) == "attacks" and r["action"] != "allow"]
    att = [r for r in rows if group_of(r["actor"]) == "attacks"]
    print(f"false positives (people refused): {len(hurt)}    attack requests refused: {len(caught)}/{len(att)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
