"""
Replay last week's log against a policy you have not deployed

A policy is a bet about how much friction real customers will tolerate, and a change to it is a new bet.
This tool replays the logged signals of every real customer against policies you did not deploy, so you
can see who a change would hurt *before* you ship it. Detection ran once (the layers); the decision can
be replayed forever. It needs the store running and a few lab weeks in its log (tools/weeks.py).

    python tools/sweep.py                          thresholds grid: blocked / challenged per (challenge_at, block_at)
    python tools/sweep.py --weight tor_exit=60     same grid with one or more weights changed (on top of the
                                                   operator's current overrides)
    python tools/sweep.py --week 2                 only one lab week of the log (default: all)
    python tools/sweep.py --signal no_pointer      who carries this signal, and what else they carry
    python tools/sweep.py --clusters               how many real customers share each campaign cluster key, i.e.
                                                   the collateral if that cluster went hot
    python tools/sweep.py --signals a,b,c          score a request that shows exactly these signals under the
                                                   current policy (no store needed)

The log holds the real customers' side of the trade-off: the cost to people. The other axis, what each
policy lets through, is the bots' side: replay the bot sessions (`--bots`) against the same policy and
read both numbers before you pick a point. Production has no actor column; here it lets the sweep grade a
change on both sides at once.
"""

import argparse
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from report import bots, by_week, flat_signals, humans, pct, persona, read_log  # noqa: E402  (puts the lab root on sys.path)
from defenses import campaign, config, correlation, policy  # noqa: E402
from defenses.sensors import BASE_SENSORS  # noqa: E402


def base_weights():
    """The shipped weights with the operator's current overrides on top."""
    return {**policy.WEIGHTS, **config.load().get("weights", {})}


def replay(rows, weights, challenge_at, block_at):
    blocked = challenged = 0
    for e in rows:
        action, _ = policy.explain(flat_signals(e), weights, challenge_at, block_at)
        blocked += action == "block"
        challenged += action == "challenge"
    return blocked, challenged


def grid(rows, weights, who):
    total = len(rows)
    print(f"{who} blocked / challenged, {total} logins, cells are (challenge_at, block_at)\n")
    block_lines = [40, 50, 60, 80, 100]
    print(f"{'challenge_at':>12} " + "".join(f"{f'block_at={b}':>18}" for b in block_lines))
    for c in [15, 20, 25, 30, 40, 50]:
        row = f"{c:>12} "
        for b in block_lines:
            if c >= b:
                row += f"{'-':>18}"
                continue
            blocked, challenged = replay(rows, weights, c, b)
            row += f"{pct(blocked, total).strip() + ' / ' + pct(challenged, total).strip():>18}"
        print(row)
    print(f"\ncurrent policy: challenge_at={policy.CHALLENGE_AT}, block_at={policy.BLOCK_AT}")


def signal_view(rows, signal, weights):
    carriers = [e for e in rows if signal in flat_signals(e)]
    print(f"{len(carriers)}/{len(rows)} real customers carry `{signal}` (weight {weights.get(signal, 0)})\n")
    print("  persona                 n   score   other signals they carry")
    by = defaultdict(list)
    for e in carriers:
        by[persona(e)].append(e)
    for p, es in sorted(by.items(), key=lambda kv: -len(kv[1])):
        others = Counter(s for e in es for s in flat_signals(e) if s != signal)
        scores = sorted(policy.score(flat_signals(e), weights) for e in es)
        print(f"  {p:<22} {len(es):>3}   {scores[0]:>3}-{scores[-1]:<3} "
              + ", ".join(f"{s} {n}" for s, n in others.most_common(4)))


def clusters(rows):
    by = defaultdict(list)
    for e in rows:
        by[e.get("cluster") or "?"].append(e)
    print(f"{len(by)} campaign clusters among {len(rows)} real customers\n")
    print(f"  {'customers':>9}  {'fail%':>5}  cluster key (JA4 | device family | ASN)")
    for key, es in sorted(by.items(), key=lambda kv: -len(kv[1]))[:12]:
        failed = sum(e["cred"] in ("wrong_password", "unknown_user") for e in es)
        print(f"  {len(es):>9}  {100 * failed / len(es):>4.0f}%  {key}")
    print("\nIf a cluster goes hot (python tools/contain.py --campaign-stepup), every customer in it gets")
    print("policy.CAMPAIGN_ACTION until the window expires. The biggest cluster is your worst-case collateral")
    print("for one attack run.")
    return 0


def score_signals(names, weights):
    """Paper exercise: what does the current policy make of a request that shows exactly these signals?"""
    layer_of = {}
    for module in BASE_SENSORS + [correlation, campaign]:
        for s in module.SIGNALS:
            layer_of[s] = module.LAYER
    unknown = [n for n in names if n not in layer_of]
    if unknown:
        print(f"Unknown signal(s): {', '.join(unknown)}\nKnown: {', '.join(sorted(layer_of))}")
        return 1
    by_layer = defaultdict(list)
    for n in names:
        by_layer[layer_of[n]].append(n)
    print(f"{'layer':<12} {'signals':<44} {'points':>6}")
    for layer, sigs in by_layer.items():
        print(f"{layer:<12} {', '.join(sigs):<44} {sum(weights.get(s, 0) for s in sigs):>6}")
    action, total = policy.explain(names, weights)
    ladder = {"challenge": f"challenge ({policy.CAMPAIGN_ACTION if 'campaign_cluster' in names else policy.DEFAULT_CHALLENGE})",
              "block": "block (answered as a wrong password)"}
    print(f"\n{total} points -> {ladder.get(action, action)}   "
          f"(challenge at {policy.CHALLENGE_AT}, block at {policy.BLOCK_AT})")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--weight", action="append", default=[], metavar="SIGNAL=POINTS")
    parser.add_argument("--week", type=int)
    parser.add_argument("--signal", metavar="SIGNAL")
    parser.add_argument("--clusters", action="store_true")
    parser.add_argument("--bots", action="store_true", help="replay the bot sessions instead of the customers")
    parser.add_argument("--signals", metavar="A,B,C", help="score a request that shows these signals")
    args = parser.parse_args()

    weights = base_weights()
    for item in args.weight:
        name, value = item.split("=")
        if name not in policy.WEIGHTS:
            print(f"Unknown signal {name}. Known: {', '.join(sorted(policy.WEIGHTS))}")
            return 1
        print(f"weight {name}: {weights[name]} -> {value}")
        weights[name] = int(value)
    if args.signals:
        return score_signals([n.strip() for n in args.signals.split(",") if n.strip()], weights)
    try:
        entries = read_log()
    except OSError:
        print("The store is not reachable. Start it (DEFENSE_LEVEL=1 python demo_site/app.py).")
        return 1
    if args.week:
        entries = by_week(entries, args.week)
    rows = bots(entries) if args.bots else [e for e in humans(entries) if not e["known_good"]]
    if not rows:
        print("No logged sessions. Replay a week first: python tools/weeks.py --week 1")
        return 1
    if args.signal:
        signal_view(rows, args.signal, weights)
    elif args.clusters:
        return clusters(rows)
    else:
        grid(rows, weights, "Bot sessions" if args.bots else "Real customers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
