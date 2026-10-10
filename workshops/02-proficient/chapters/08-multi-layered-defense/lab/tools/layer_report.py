"""
Chapter 8, Round 0: What each layer says about real customers

Shadow mode (DEFENSE_LEVEL=0) scores every login and blocks nothing, which
makes it the only safe way to learn what a new layer would do to your real
users before it is allowed to decide anything. This report reads the
decision log and answers, per layer and per signal:

  - how many real customers it fired on, and which personas they were
  - what would happen if that layer alone were allowed to block (Round 1's
    veto chain), and how those slices add up across layers

Run the population first, then:
    python tools/population.py && python tools/layer_report.py
"""

import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "defenses"))

import policy  # noqa: E402
import veto  # noqa: E402
from report import humans, pct, persona, read_log  # noqa: E402


def main():
    people = humans(read_log())
    if not people:
        print("No logged human sessions. Run `python tools/population.py` first.")
        return 1
    total = len(people)
    print(f"=== Layer report: {total} real customers (shadow mode) ===\n")

    print(f"{'layer':<12} {'signal':<24} {'humans':>7}  {'weight':>6}  personas hit")
    by_signal = defaultdict(Counter)
    layer_hits = defaultdict(set)
    for e in people:
        for layer, sigs in e["signals"].items():
            for s in sigs:
                by_signal[(layer, s)][persona(e)] += 1
            if sigs:
                layer_hits[layer].add(e["sid"])
    for (layer, s), who in sorted(by_signal.items(), key=lambda kv: (kv[0][0], -sum(kv[1].values()))):
        n = sum(who.values())
        tops = ", ".join(f"{p} {c}" for p, c in who.most_common(3))
        print(f"{layer:<12} {s:<24} {pct(n, total):>7}  {policy.WEIGHTS.get(s, 0):>6}  {tops}")

    print("\nIf each layer blocked on its own line (Round 1's veto chain):")
    print(f"{'layer':<12} {'line':>5} {'humans blocked':>15}")
    union, total_rate = set(), 0.0
    for e in people:
        points = veto.layer_points(e["signals"])
        for layer, pts in points.items():
            if layer in veto.VETO_AT and pts >= veto.VETO_AT[layer]:
                layer_hits.setdefault(f"veto:{layer}", set()).add(e["sid"])
    for layer, line in veto.VETO_AT.items():
        hit = layer_hits.get(f"veto:{layer}", set())
        union |= hit
        total_rate += len(hit) / total
        print(f"{layer:<12} {line:>5} {pct(len(hit), total):>15}")
    print(f"{'sum of layers':<18} {pct(round(total_rate * total), total):>15}   (if nobody tripped two)")
    print(f"{'union (actual)':<18} {pct(len(union), total):>15}   <- what the veto chain would block")
    print("\nEvery one of these is a real customer. Round 1 turns this table into 403s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
