"""
Chapter 8, Rounds 2 and 4: Choosing the operating point

A policy is a bet about how much friction real customers will tolerate. This
tool replays the logged signals of every real customer against policies you
did not deploy, so you can see who a change would hurt *before* you ship it.
Detection runs once (the sensors); the decision can be replayed forever.

    python tools/sweep.py                       thresholds grid: blocked / challenged per (challenge_at, block_at)
    python tools/sweep.py --weight tor_exit=60  same grid with one or more weights changed
    python tools/sweep.py --signal no_pointer   who carries this signal, and what else they carry
    python tools/sweep.py --clusters            Round 4: how many real customers share each campaign
                                                cluster key, i.e. the collateral if that cluster went hot
    python tools/sweep.py --signals a,b,c       score a request that shows exactly these signals under
                                                the veto chain and under the current policy

The log holds only real customers, so this shows one axis of the trade-off:
the cost to people. The other axis, what each policy lets through, comes
from the attacker profiles described in the chapter and from the campaign
math in campaign.py. Keep both in view when you pick a point.
"""

import argparse
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "defenses"))

import campaign  # noqa: E402
import correlation  # noqa: E402
import policy  # noqa: E402
import veto  # noqa: E402
from sensors import BASE_SENSORS  # noqa: E402
from report import CHALLENGES, flat_signals, humans, pct, persona, read_log  # noqa: E402


def replay(people, weights, challenge_at, block_at):
    blocked = challenged = 0
    for e in people:
        action, _ = policy.decide(flat_signals(e), weights, challenge_at, block_at)
        blocked += action == "block"
        challenged += action in CHALLENGES
    return blocked, challenged


def grid(people, weights):
    total = len(people)
    print(f"Real customers blocked / challenged, {total} logins, cells are (challenge_at, block_at)\n")
    blocks = [40, 50, 60, 80, 100]
    print(f"{'challenge_at':>12} " + "".join(f"{f'block_at={b}':>18}" for b in blocks))
    for c in [15, 20, 25, 30, 40, 50]:
        row = f"{c:>12} "
        for b in blocks:
            if c >= b:
                row += f"{'-':>18}"
                continue
            blocked, challenged = replay(people, weights, c, b)
            row += f"{pct(blocked, total).strip() + ' / ' + pct(challenged, total).strip():>18}"
        print(row)
    print(f"\ncurrent policy: challenge_at={policy.CHALLENGE_AT}, block_at={policy.BLOCK_AT}")


def signal_view(people, signal):
    carriers = [e for e in people if signal in flat_signals(e)]
    print(f"{len(carriers)}/{len(people)} real customers carry `{signal}` "
          f"(weight {policy.WEIGHTS.get(signal, 0)})\n")
    print("  persona                 n   score   other signals they carry")
    by = defaultdict(list)
    for e in carriers:
        by[persona(e)].append(e)
    for p, es in sorted(by.items(), key=lambda kv: -len(kv[1])):
        others = Counter(s for e in es for s in flat_signals(e) if s != signal)
        scores = sorted(e["score"] for e in es)
        print(f"  {p:<22} {len(es):>3}   {scores[0]:>3}-{scores[-1]:<3} "
              + ", ".join(f"{s} {n}" for s, n in others.most_common(4)))


def clusters(people):
    by = defaultdict(list)
    for e in people:
        by[e["cluster"]].append(e)
    print(f"{len(by)} campaign clusters among {len(people)} real customers\n")
    print(f"  {'customers':>9}  {'fail%':>5}  cluster key (JA4 | device family | ASN)")
    for key, es in sorted(by.items(), key=lambda kv: -len(kv[1])):
        failed = sum(e["cred"] != "valid" for e in es)
        print(f"  {len(es):>9}  {100 * failed / len(es):>4.0f}%  {key}")
    print("\nIf a cluster goes hot, every customer in it gets CAMPAIGN_ACTION until the window")
    print("expires. The biggest cluster is your worst-case collateral for one attack run.")


def score_signals(names):
    """Round 1-4 paper exercise: what does each decision engine make of a request
    that shows exactly these signals? Describe the attacker, don't run it."""
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
    print(f"{'layer':<12} {'signals':<44} {'points':>6} {'veto line':>9}  veto?")
    for layer, sigs in by_layer.items():
        pts = sum(policy.WEIGHTS.get(s, 0) for s in sigs)
        line = veto.VETO_AT.get(layer)
        verdict = "-" if line is None else ("BLOCK" if pts >= line else "under")
        print(f"{layer:<12} {', '.join(sigs):<44} {pts:>6} {str(line) if line else '-':>9}  {verdict}")
    v_action, v_layer = veto.decide(by_layer)
    p_action, total = policy.decide(names)
    print(f"\nveto chain (level 1):   {v_action}" + (f" by {v_layer}" if v_layer else ""))
    print(f"risk score (level 2+):  {total} points -> {p_action}   "
          f"(challenge at {policy.CHALLENGE_AT}, block at {policy.BLOCK_AT})")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--weight", action="append", default=[], metavar="SIGNAL=POINTS")
    parser.add_argument("--signal", metavar="SIGNAL")
    parser.add_argument("--clusters", action="store_true")
    parser.add_argument("--signals", metavar="A,B,C", help="score a request that shows these signals")
    args = parser.parse_args()

    if args.signals:
        return score_signals([n.strip() for n in args.signals.split(",") if n.strip()])
    people = humans(read_log())
    if not people:
        print("No logged human sessions. Run a checkpoint or `python tools/population.py` first.")
        return 1
    weights = dict(policy.WEIGHTS)
    for item in args.weight:
        name, value = item.split("=")
        if name not in weights:
            print(f"Unknown signal {name}. Known: {', '.join(sorted(weights))}")
            return 1
        weights[name] = int(value)
        print(f"weight {name}: {policy.WEIGHTS[name]} -> {value}")
    if args.signal:
        signal_view(people, args.signal)
    elif args.clusters:
        clusters(people)
    else:
        grid(people, weights)
    return 0


if __name__ == "__main__":
    sys.exit(main())
