"""
The replayer: five weeks of operations in a few minutes

    python tools/weeks.py --week 1          replay week 1 (customers + that week's bots)
    python tools/weeks.py --through 3       replay weeks 1..3 in order
    python tools/weeks.py --week 4 --quiet  no per-week summary (the checkpoint uses this)

Each week it builds the 200 customers and 10 monitors (tools/personas_ch8.py) and the week's
adversary sessions (attacks/weekN_*.py), merges them by lab clock so the decision log reads in
calendar order, and sends each one through the live store, one at a time (so the per-address and
per-cluster counters see the same order on every run and the numbers are exact). Every request
carries the lab calendar (`Lab-Week`, `Lab-Clock`), so every tool downstream (health, drift, gate,
ops) can slice the log by week.

It expires the windowed counters at each week boundary (POST /lab/ops/new-week), because velocity and
campaign windows are minutes of wall clock, not lab weeks; without that, week 5's low-and-slow run
would share a counter with week 1.

Ground truth (who was really a bot) is the actor label on each decision row, the one thing the
scoreboard grades by and production never has.
"""

import argparse
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(HERE, "..")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(LAB, "attacks"))

import labclient  # noqa: E402
import personas_ch8  # noqa: E402

ATTACKS = {1: "week1_baseline", 2: "week2_burned_signal", 3: "week3_hidden_switch",
           4: "week4_label_poison", 5: "week5_humanized_farm",
           6: "week5_humanized_farm"}   # week 6: the same farm, now under containment


def new_week():
    return labclient.admin("POST", "/lab/ops/new-week")


def adversary_sessions(week):
    module = __import__(ATTACKS[week])
    return module.sessions(week)


def replay_week(week, quiet=False):
    new_week()
    customers = [(p["clock"], ("human", p)) for p in personas_ch8.make_people(week) + personas_ch8.make_monitors(week)]
    bots = [(clock, ("bot", run)) for clock, run in adversary_sessions(week)]
    schedule = sorted(customers + bots, key=lambda t: t[0])

    outcomes = {"human": Counter(), "bot": Counter()}
    for _, (kind, payload) in schedule:
        outcome, _ = personas_ch8.visit(payload, week) if kind == "human" else payload()
        outcomes[kind][outcome] += 1
    if not quiet:
        h, b = outcomes["human"], outcomes["bot"]
        print(f"week {week}: {sum(h.values())} customers ("
              + ", ".join(f"{k} {v}" for k, v in sorted(h.items())) + "), "
              + f"{sum(b.values())} bots ("
              + ", ".join(f"{k} {v}" for k, v in sorted(b.items())) + ")")
    return outcomes


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--week", type=int, choices=range(1, 7))
    group.add_argument("--through", type=int, choices=range(1, 7))
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    labclient.wait_for_store()
    weeks = [args.week] if args.week else range(1, args.through + 1)
    started = time.perf_counter()
    for week in weeks:
        replay_week(week, args.quiet)
    if not args.quiet:
        print(f"  ({time.perf_counter() - started:.1f}s of wall clock)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
