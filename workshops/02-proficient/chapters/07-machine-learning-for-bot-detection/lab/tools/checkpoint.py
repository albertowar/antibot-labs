"""
Chapter 7 — Round Checkpoint (Section 7.6)

Run at the end of every round. It sends fresh traffic at the running demo
site (simulated real users mixed with every attack seen so far) and prints
the scoreboard: bot success, real users blocked per cohort, scoring
latency and attacker spend, each checked against the expected results.

Fell behind? --catch-up rebuilds the reference state for the round
(traffic, labels, models) with the reference code, then runs the check:

    python tools/checkpoint.py --round 2 --catch-up

--catch-up works at any DEFENSE_LEVEL. Restart the site at the round's
level before the final check if it tells you to.

Start completely fresh (wipes the database, labels, truth and models):

    python tools/checkpoint.py --reset
"""

import argparse
import glob
import json
import os
import random
import subprocess
import sys
import urllib.request

import labnet
import scoreboard
import shopper
import simulate

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "defenses"))

LAB = os.path.join(os.path.dirname(__file__), "..")
PY = sys.executable

# (min, max, label) on the share of checkouts that succeed, per attack and DEFENSE_LEVEL
EXPECT = {
    0: {"round0_baseline": (0.9, 1.0, "succeeds")},
    1: {"round0_baseline": (0.0, 0.05, "≤ 5%"), "round1_humanized": (0.7, 1.0, "gets through")},
    2: {"round0_baseline": (0.0, 0.05, "≤ 5%"), "round1_humanized": (0.0, 0.20, "≤ 20%"),
        "round2_farm": (0.6, 1.0, "gets through")},
    3: {"round0_baseline": (0.0, 0.05, "≤ 5%"), "round1_humanized": (0.0, 0.10, "≤ 10%"),
        "round2_farm": (0.0, 0.15, "≤ 15%"), "round3_oracle_prober": (0.6, 1.0, "gets through")},
    4: {"round0_baseline": (0.0, 0.05, "≤ 5%"), "round1_humanized": (0.0, 0.10, "≤ 10%"),
        "round2_farm": (0.0, 0.15, "≤ 15%"), "round3_oracle_prober": (0.0, 0.10, "≤ 10%")},
}
# Share of simulated real users you accept blocking, per level
HUMAN_BUDGET = {0: 0.0, 1: 0.03, 2: 0.03, 3: 0.04, 4: 0.04}


def status():
    with urllib.request.urlopen(f"{labnet.target()}/lab/status", timeout=5) as r:
        return json.loads(r.read())


def step(title, *cmd):
    print(f"\n▶ {title}: {' '.join(cmd)}", flush=True)
    subprocess.run([PY, *cmd], cwd=LAB, check=True)


def catch_up(rnd, server_level):
    """Rebuild the reference state for round `rnd`, reusing whatever already exists."""
    from store import make_engine
    with make_engine().connect() as conn:
        n_orders = conn.exec_driver_sql("SELECT COUNT(*) FROM orders").scalar()
    if n_orders < 500:
        step("Round 0 traffic", "tools/simulate.py")
    if rnd >= 1:
        step("Round 1 model", "defenses/train.py", "--round", "1")
    if rnd >= 2:
        if not any("round1_humanized" in line for line in open(shopper.TRUTH_FILE)):
            step("Round 1 attack traffic", "attacks/round1_humanized.py")
        step("Round 2 cluster labels", "tools/label_cluster.py", "--yes")
        step("Round 2 model", "defenses/train.py", "--round", "2")
    if rnd >= 3:
        step("Round 3 anomaly model", "defenses/anomaly.py")
    want = min(rnd, 4)
    if server_level != want:
        print(f"\n✅ Caught up. Now restart the demo site at the round's level and re-run:"
              f"\n     DEFENSE_LEVEL={want} python demo_site/app.py"
              f"\n     python tools/checkpoint.py --round {rnd}")
        sys.exit(0)


def reset():
    from store import make_engine, reset_db
    reset_db(make_engine())
    for path in [shopper.TRUTH_FILE, os.path.join(LAB, "data", "manual_labels.jsonl"),
                 *glob.glob(os.path.join(LAB, "artifacts", "*"))]:
        if os.path.basename(path) != ".gitkeep" and os.path.exists(path):
            os.remove(path)
    print("Database, labels, ground truth and models wiped. Restart the demo site.")


def run_check(rnd, seed):
    level = min(rnd, 4)
    personas = simulate.legit_personas(200, seed=seed)
    personas += load("round0_baseline").personas(n_each=20, seed=seed)
    if rnd >= 1:
        personas += load("round1_humanized").personas(n=30, seed=seed)
    if rnd >= 2:
        personas += load("round2_farm").personas(n=30, seed=seed)
    random.Random(seed).shuffle(personas)
    print(f"Sending {len(personas)} sessions (200 real users + attacks so far)...")
    results = shopper.run_sessions(personas, seed=seed, run=f"checkpoint-{rnd}")
    extra_usd = {}
    if rnd >= 3:
        print("Running the oracle prober (probe, then exploit)...")
        prober = load("round3_oracle_prober")
        results += prober.run(seed=seed, quiet=True)
        s = prober.run.stats
        extra_usd["round3_oracle_prober"] = s["probe_usd"]
        print(f"  prober: {s['probes']} probe sessions, chose {prober.fmt(s['config'])}")
    print()
    return scoreboard.report(results, EXPECT[level], HUMAN_BUDGET[level], extra_usd)


def load(name):
    return simulate.load_attack(name)


def main():
    parser = argparse.ArgumentParser(description="Round checkpoint: measure both sides.")
    parser.add_argument("--round", type=int, choices=range(0, 5))
    parser.add_argument("--catch-up", action="store_true", help="rebuild this round's reference state")
    parser.add_argument("--reset", action="store_true", help="wipe all lab state and exit")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    if args.reset:
        reset()
        return 0
    if args.round is None:
        parser.error("--round is required")
    try:
        st = status()
    except OSError:
        print(f"❌ Demo site not reachable on {labnet.target()}. Is it running?")
        return 1
    if args.catch_up:
        catch_up(args.round, st["level"])
        st = status()

    want = min(args.round, 4)
    print(f"=== Checkpoint: Round {args.round} (server at DEFENSE_LEVEL={st['level']}, "
          f"scoring {st['scoring']}) ===\n")
    if st["level"] != want:
        print(f"❌ Expected DEFENSE_LEVEL={want}. Restart the demo site with:")
        print(f"     DEFENSE_LEVEL={want} python demo_site/app.py")
        return 1
    if st["scoring"].get("missing"):
        print(f"❌ Missing model files {st['scoring']['missing']}. "
              f"Train them, or run with --catch-up.")
        return 1

    failures = run_check(args.round, args.seed if args.seed is not None else 100 + args.round)
    print(f"\n{'✅' if not failures else '❌'} Round {args.round} checkpoint "
          f"{'passed' if not failures else f'failed ({failures} expectations)'}.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
