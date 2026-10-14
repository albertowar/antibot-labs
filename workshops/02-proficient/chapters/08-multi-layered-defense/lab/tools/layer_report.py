"""
Chapter 8, Round 0: which layer fires on which real customers?

Run it after a Round 0 checkpoint (shadow mode: every layer runs, nothing is enforced). The first
table shows, for each layer, how many of the logged logins carry one of its signals and who they
are; the second, how many each layer would BLOCK if it were allowed to decide alone (its points
reach its veto line). Layers overlap very little, which is why a veto chain's false positives add
up: the sum of the second table is close to its union.

    python tools/layer_report.py
"""

import sys
from collections import Counter, defaultdict

from report import attempts, layers, pct, persona, read_log
from defenses import policy, veto


def main():
    rows = attempts(read_log())
    if not rows:
        print("No logged human logins. Run `python tools/checkpoint.py --round 0` first.")
        return 1
    total = len(rows)
    print(f"{total} real logins (level {rows[0]['level']}); per layer, how many carry one of its signals\n")
    print(f"  {'layer':<12} {'logins':>6} {'share':>7}  top signals                       who")
    by_layer = defaultdict(list)
    for r in rows:
        for layer, names in layers(r).items():
            by_layer[layer].append((r, names))
    for layer, hits in sorted(by_layer.items(), key=lambda kv: -len(kv[1])):
        sigs = Counter(n for _, names in hits for n in names)
        who = Counter(persona(r) for r, _ in hits)
        print(f"  {layer:<12} {len(hits):>6} {pct(len(hits), total):>7}  "
              f"{', '.join(f'{s} {n}' for s, n in sigs.most_common(3)):<33} "
              f"{', '.join(f'{p} {n}' for p, n in who.most_common(3))}")
    alone = Counter()
    union = []
    for r in rows:
        points = {layer: sum(policy.WEIGHTS.get(n, 0) for n in names) for layer, names in layers(r).items()}
        over = [layer for layer, line in veto.VETO_AT.items() if points.get(layer, 0) >= line]
        alone.update(over)
        if over:
            union.append((r, over))
    print(f"\n  would block alone (points >= the layer's veto line)")
    for layer, n in alone.most_common():
        print(f"  {layer:<12} {n:>6} {pct(n, total):>7}")
    both = [r for r, over in union if len(over) > 1]
    print(f"  {'sum':<12} {sum(alone.values()):>6} {pct(sum(alone.values()), total):>7}      "
          f"union {len(union)} ({pct(len(union), total).strip()}); over two or more lines: "
          + (", ".join(f"{r['actor'].split(':')[1]}:{r['actor'].split(':')[2]}" for r in both) or "none"))
    flagged = sum(1 for r in rows if layers(r))
    print(f"\n{flagged}/{total} logins ({pct(flagged, total).strip()}) carry at least one signal; "
          f"{total - flagged} are clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
