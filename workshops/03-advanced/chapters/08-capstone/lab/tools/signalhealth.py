"""
Capstone — signal health, the local Grafana stand-in (W3 Ch4)

Operating a stack is not just scoring traffic; it is watching whether each
signal is still firing. A layer that goes quiet has either been bypassed or has
drifted — either way you want to know before the attacker tells you. This tool
reads the decisions table (/admin/decisions) and prints, per layer:

    trigger rate   how often this layer contributed points (of all decisions)
    outcomes       allow / challenge / block / deny counts by action
    stream CV       the inter-request CV spread, so you can see the low-and-slow
                    band separating from the humans

With the optional `prod` Docker profile this same data is scraped by Prometheus
and drawn in Grafana (http://localhost:3000); without it, this is the console
version. In the final debrief, run it during an attack and watch the layers
light up — a silent layer during an attack window is a finding.

Run (store running):
    python tools/signalhealth.py
    python tools/signalhealth.py --action graphql
"""

import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import admin, ensure_local  # noqa: E402

LAYER = re.compile(r"\[(L\d)\]")
LAYERS = ["L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7"]
LAYER_NAME = {"L0": "request/TLS/rate", "L1": "fingerprint", "L2": "behavior", "L3": "session model",
              "L4": "login/token", "L5": "API hardening", "L6": "streaming", "L7": "supply chain"}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--action", help="filter to one action (buy, login, graphql, api_rest, register)")
    args = parser.parse_args()
    ensure_local()
    params = {"limit": 5000}
    if args.action:
        params["action"] = args.action
    rows = admin("GET", "/admin/decisions", params=params)
    if not rows:
        print("No decisions recorded yet. Run an attack or tools/checkpoint.py first.")
        return 0

    print(f"=== Signal health over {len(rows)} decisions ===\n")

    by_action = collections.defaultdict(lambda: collections.Counter())
    for d in rows:
        by_action[d["action"]][d["outcome"]] += 1
    print("Outcomes by action")
    for action, counts in sorted(by_action.items()):
        total = sum(counts.values())
        parts = " ".join(f"{k} {v}" for k, v in sorted(counts.items()))
        print(f"  {action:<10} {total:>4}  |  {parts}")

    print("\nLayer trigger rate (how often each layer contributed a reason)")
    fired = collections.Counter()
    for d in rows:
        tags = set()
        for reason in d.get("reasons", []):
            m = LAYER.search(reason)
            if m:
                tags.add(m.group(1))
        # shadow-mode layers also 'fire' for health, even when they don't act
        for tag in (d.get("shadow") or {}):
            tags.add(tag)
        for tag in tags:
            fired[tag] += 1
    n = len(rows)
    for layer in LAYERS:
        count = fired.get(layer, 0)
        bar = "#" * int(round(30 * count / n)) if n else ""
        flag = "  ⚠️ silent" if count == 0 else ""
        print(f"  {layer} {LAYER_NAME[layer]:<16} {count:>4}/{n}  {bar}{flag}")

    print("\nTip: a layer that is silent during an attack window is a finding — it was "
          "bypassed or has drifted. That is the question the debrief asks of every layer.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
