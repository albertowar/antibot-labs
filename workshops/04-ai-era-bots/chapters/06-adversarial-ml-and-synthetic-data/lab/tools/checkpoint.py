"""
W4 Ch6 — Round checkpoint: measure both sides of the adversarial-ML arms race

Run at the end of every round against the demo site at DEFENSE_LEVEL=1 (the
deployed stack: model + anomaly + oracle guard). Round 0 collects the base
data at DEFENSE_LEVEL=0 (log only). Each round has its own metric:

  Round 1  surrogate fidelity   how well an extractor clones the model
  Round 2  evasion success      transfer evasion from the clone
  Round 3  privacy block rate   poisoning turned the retrain on real users
  Round 4  rare-class success   the barely-labelled family

Every round also reports real users blocked (the cost) and the attacker's
simulated spend.

Fell behind, or want the reference defense? --catch-up rebuilds this round's
state with the solution code (copies solutions/round{1..N}/* into defenses/,
retrains the model, injects the round's traffic), then tells you to restart:

    python tools/checkpoint.py --round 2 --catch-up
    DEFENSE_LEVEL=1 python demo_site/app.py        # restart to load the model/guard
    python tools/checkpoint.py --round 2

Start completely fresh (wipes the database, labels, truth, models, surrogate):

    python tools/checkpoint.py --reset
"""

import argparse
import glob
import json
import os
import random
import shutil
import subprocess
import sys
import urllib.request
from collections import defaultdict

import labclient  # noqa: E402,F401  (puts defenses/ on sys.path)
import scoreboard
import shopper
import simulate

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "defenses"))

LAB = os.path.join(os.path.dirname(__file__), "..")
PY = sys.executable
SOLUTIONS = os.path.join(LAB, "solutions")
DEFENSES = os.path.join(LAB, "defenses")
QUERIES = 160   # extractor probe budget in Round 1

# Pass criteria per round (the newest attack must be contained).
EXPECT = {
    1: {"metric": "surrogate fidelity", "max": 0.80},
    2: {"metric": "evasion success", "max": 0.20},
    3: {"metric": "privacy_browser blocked", "max": 0.15},
    4: {"metric": "rare-class success", "max": 0.25},
}
# Share of simulated real users you accept blocking overall, per round.
HUMAN_BUDGET = {0: 1.0, 1: 0.05, 2: 0.05, 3: 0.08, 4: 0.08}


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
import labnet  # noqa: E402


def status():
    with urllib.request.urlopen(f"{labnet.target()}/lab/status", timeout=5) as r:
        return json.loads(r.read())


def step(title, *cmd):
    print(f"\n▶ {title}: {' '.join(cmd)}", flush=True)
    subprocess.run([PY, *cmd], cwd=LAB, check=True)


def load(name):
    return simulate.load_attack(name)


def copy_solutions(rnd):
    installed = labnet.catch_up(LAB, rnd)
    print(f"  installed solutions/round1..{rnd} -> " + ", ".join(installed) + "   (your versions kept as .bak; --restore puts them back)")


def n_orders():
    from store import make_engine
    with make_engine().connect() as conn:
        return conn.exec_driver_sql("SELECT COUNT(*) FROM orders").scalar()


def catch_up(rnd):
    """Rebuild this round's reference state with the solution code, then stop."""
    if n_orders() < 600:
        step("Round 0 traffic (real users + baseline bots)", "tools/simulate.py")
    step("Base model", "defenses/baseline_model.py")
    step("Anomaly detector", "defenses/anomaly.py")
    if rnd >= 1:
        copy_solutions(rnd)
    if rnd >= 2:
        print("\n▶ Round 1 extraction (build the surrogate)")
        load("round1_extract").run(seed=61, queries=QUERIES, quiet=True)
        print("▶ Round 2 evasion (capture adversarial examples)")
        load("round2_evade").run(n=40, seed=72, quiet=True)
        step("Robust model v3 (adversarial + monotone)", "defenses/robust_train.py")
    if rnd >= 3:
        print("\n▶ Round 3 poisoning (inject the privacy-lookalike burst)")
        load("round3_poison").run(n=120, seed=83, quiet=True)
        step("Sanitized model v4 (provenance)", "defenses/provenance.py")
    if rnd >= 4:
        print("\n▶ Round 4 rare-class traffic (a few get labelled)")
        load("round4_rareclass").run(n=60, seed=94, quiet=True)
        step("Augmented model v5 (SMOTE)", "defenses/augment.py")
    print(f"\n✅ Caught up for Round {rnd}. Restart the site so it loads the "
          f"new model and guard, then re-run the checkpoint:\n"
          f"     DEFENSE_LEVEL={min(rnd,1)} python demo_site/app.py\n"
          f"     python tools/checkpoint.py --round {rnd}")


def reset():
    from store import make_engine, reset_db
    reset_db(make_engine())
    gone = [shopper.TRUTH_FILE,
            os.path.join(LAB, "data", "surrogate.txt"),
            os.path.join(LAB, "data", "surrogate.json"),
            os.path.join(LAB, "data", "adversarial.parquet"),
            *glob.glob(os.path.join(LAB, "artifacts", "*"))]
    for path in gone:
        if os.path.basename(path) != ".gitkeep" and os.path.exists(path):
            os.remove(path)
    print("Database, truth, models, surrogate and adversarial captures wiped.")


def human_block(results):
    """{cohort: [blocked, total]} for simulated real users."""
    h = defaultdict(lambda: [0, 0])
    for r in results:
        if r["is_bot"] or str(r["final"]).startswith("error"):
            continue
        c = h[r["cohort"]]
        c[0] += not shopper.succeeded(r)
        c[1] += 1
    return h


def pct(n, d):
    return f"{n}/{d} ({n / d:.0%})" if d else "-"


def run_check(rnd, seed):
    # Real users (+ a few baseline bots for context) at the round's level
    personas = simulate.legit_personas(200, seed=seed)
    personas += load("round0_baseline").personas(n_each=12, seed=seed)
    random.Random(seed).shuffle(personas)
    print(f"Sending {len(personas)} sessions (200 real users + baseline bots)...")
    results = shopper.run_sessions(personas, seed=seed, run=f"checkpoint-{rnd}")

    failures = 0
    attack_usd = 0.0
    metric_name = EXPECT[rnd]["metric"]
    metric_cap = EXPECT[rnd]["max"]

    if rnd == 1:
        print("Extracting the model (concentrated datacenter probes)...")
        st = load("round1_extract").run(seed=seed + 300, queries=QUERIES, quiet=True)
        metric_val, attack_usd = st["fidelity"], st["usd"]
        extra = f"{st['queries']} queries, ${attack_usd:.2f}"
    elif rnd == 2:
        print("Running the transfer evasion from the surrogate...")
        load("round2_evade").run(n=40, seed=seed + 300, quiet=True)
        st = load("round2_evade").run.stats
        metric_val, attack_usd = st["ok"] / st["n"], st["usd"]
        extra = " ".join(f"{k}={st['config'][k]}" for k in ("pool", "js", "behavior"))
    elif rnd == 3:
        pb = human_block(results)["privacy_browser"]
        metric_val = pb[0] / pb[1] if pb[1] else 0.0
        extra = f"{pb[0]}/{pb[1]} real privacy-browser users blocked"
    else:  # rnd == 4
        print("Running the rare mobile-reseller family...")
        load("round4_rareclass").run(n=40, seed=seed + 300, quiet=True)
        st = load("round4_rareclass").run.stats
        metric_val, attack_usd = st["ok"] / st["n"], st["usd"]
        extra = f"{st['ok']}/{st['n']} checkouts confirmed"

    good = metric_val <= metric_cap
    failures += not good
    print(f"\n{'✅' if good else '❌'} {metric_name}: {metric_val:.0%}   "
          f"(target ≤ {metric_cap:.0%}; {extra})")

    # Real-user cost, always
    h = human_block(results)
    print("\nReal users (simulated cohorts)      blocked")
    tb = tt = 0
    for cohort, (b, n) in sorted(h.items()):
        tb += b
        tt += n
        flag = "  ⚠️" if n and b / n > 0.15 else ""
        print(f"     {cohort:<22} {pct(b, n)}{flag}")
    budget = HUMAN_BUDGET[rnd]
    hb_ok = tt == 0 or tb / tt <= budget
    failures += not hb_ok
    print(f"  {'✅' if hb_ok else '❌'} total {pct(tb, tt)}   (budget ≤ {budget:.0%})")

    lat = scoreboard.latency(results)
    if lat:
        print(f"\nDefender cost   ML scoring: median {lat[0]:.1f} ms, p95 {lat[1]:.1f} ms")
    if attack_usd:
        print(f"Attacker cost   ≈ ${attack_usd:.2f} simulated proxy/fingerprint spend")
    return failures


def main():
    parser = argparse.ArgumentParser(description="W4 Ch6 round checkpoint.")
    parser.add_argument("--round", type=int, choices=range(0, 5))
    parser.add_argument("--catch-up", action="store_true",
                        help="rebuild this round's state with the solution code, then stop")
    parser.add_argument("--restore", action="store_true", help="put your .bak files back, then exit")
    parser.add_argument("--reset", action="store_true", help="wipe all lab state and exit")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()
    if args.restore:
        restored = labnet.restore(LAB)
        print("restored: " + (", ".join(restored) or "nothing to restore (no .bak files)"))
        return 0

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
        catch_up(args.round)
        return 0

    want = min(args.round, 1)
    print(f"=== Checkpoint: Round {args.round} (server at DEFENSE_LEVEL={st['level']}, "
          f"scoring {st['scoring']}) ===\n")
    if st["level"] != want:
        print(f"❌ Expected DEFENSE_LEVEL={want}. Restart the demo site with:")
        print(f"     DEFENSE_LEVEL={want} python demo_site/app.py")
        return 1
    if args.round == 0:
        print("Round 0 is data collection: run tools/simulate.py, then move to Round 1.")
        return 0
    if st["scoring"].get("missing"):
        print(f"❌ Missing model files {st['scoring']['missing']}. Run with --catch-up.")
        return 1

    failures = run_check(args.round, args.seed if args.seed is not None else 100 + args.round)
    print(f"\n{'✅' if not failures else '❌'} Round {args.round} checkpoint "
          f"{'passed' if not failures else f'failed ({failures} expectation(s))'}.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
