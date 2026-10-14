"""
Drop-day traffic: simulated real users (+ the usual bots), then the store's log becomes the history

Generates the traffic your model learns from. 600 real users in six cohorts (tools/personas_ch7.py)
interleaved with 300 baseline scalpers (attacks/round0_baseline.py), all through the running store at
DEFENSE_LEVEL 0 (nothing scored, every order confirmed), then pulls the store's event log into
data/history/ (tools/analyst.py). Deterministic from --seed; the history is generated, gitignored.

    python tools/simulate.py                    # the drop day: 600 users + 300 baseline bots (about 2 min)
    python tools/simulate.py --no-bots          # real users only
    python tools/simulate.py --wave round1_humanized   # ONE attack wave, appended to the history (Round 2)
"""

import argparse
import importlib.util
import os
import random
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import analyst  # noqa: E402
import labclient  # noqa: E402
import personas_ch7  # noqa: E402
import shopper  # noqa: E402
from defenses import history  # noqa: E402

ATTACKS_DIR = os.path.join(HERE, "..", "attacks")
DROP_STOCK = 20000        # a drop day is thousands of orders; the starter's 50 would sell out in seconds


def load_attack(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ATTACKS_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, ATTACKS_DIR)
    spec.loader.exec_module(module)
    return module


def drop_day(humans=600, bots=True, seed=1):
    personas = personas_ch7.legit_personas(humans, seed)
    if bots:
        personas += load_attack("round0_baseline").personas(n_each=150, seed=seed)
    random.Random(seed).shuffle(personas)
    return shopper.run_sessions(personas, seed=seed)


def main():
    parser = argparse.ArgumentParser(description="Generate drop-day traffic.")
    parser.add_argument("--humans", type=int, default=600)
    parser.add_argument("--no-bots", action="store_true")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--wave", default=None, help="run one attack from attacks/ and append it to the history")
    args = parser.parse_args()

    labclient.wait_for_store()
    level = labclient.admin("GET", "/lab/status")["level"]
    labclient.set_level(0)                                   # history is collected with nothing scored
    try:
        if args.wave:
            labclient.reset(stock=DROP_STOCK)
            attack = load_attack(args.wave)
            results = attack.run(attack.HISTORY_N, attack.HISTORY_SEED)
            print(f"=== wave {args.wave}: {len(results)} sessions -> {labclient.BASE_URL} ===")
        else:
            history.reset()
            labclient.reset(stock=DROP_STOCK)
            print(f"=== Drop day: {args.humans} real users{'' if args.no_bots else ' + 300 baseline bots'} -> {labclient.BASE_URL} ===")
            results = drop_day(args.humans, not args.no_bots, args.seed)
        by = Counter((r["actor"].rsplit(":", 1)[0], r["final"]) for r in results)
        for (actor, final), n in sorted(by.items(), key=str):
            print(f"  {actor:<28} {str(final):<10} {n}")
        new = analyst.pull()
        print(f"\n{len(results)} sessions; {new} appended to data/history/ (log.jsonl, truth.jsonl)")
    finally:
        labclient.set_level(level)


if __name__ == "__main__":
    main()
