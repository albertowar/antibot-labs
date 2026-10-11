"""
W4 Ch6 — Round 1 Attack: steal the model (Section 6.3)

The defender's model is now an ASSET. You do not have its file, but you can
query it: every checkout returns a verdict (allowed or blocked), and the
site has to give you that verdict because it has to act on it. One bit per
query. Tramèr et al. (2016) showed that is enough to clone a model through
its prediction API; Papernot et al. (2017) showed the clone transfers.

This attack is *decision-based* model extraction. We send cheap probe
sessions across the knob space (attacks/advlib.py), read the one-bit
verdict, and fit a SURROGATE on (knobs -> verdict). The surrogate is our
private, offline copy of the defender's decision boundary. Round 2 uses it
to find an evasion without ever touching the real model again.

The metric is FIDELITY: on a fresh held-out set of configs, how often does
the surrogate agree with the real model? High fidelity from few queries is
the whole game.

  - no guard (stub oracle_guard)      → fidelity ~95-100%, a near-perfect clone
  - query budget + boundary noise      → fidelity capped well below that, and
    (defenses/oracle_guard.py solution)   the clone costs far more queries

Run (demo site up at DEFENSE_LEVEL=1):
    python attacks/round1_extract.py
    python attacks/round1_extract.py --queries 128
"""

import argparse
import json
import os
import random
import sys

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import advlib  # noqa: E402
import labnet  # noqa: E402
import shopper  # noqa: E402

DATA = os.path.join(os.path.dirname(__file__), "..", "data")
SURROGATE = os.path.join(DATA, "surrogate.txt")
SURROGATE_META = os.path.join(DATA, "surrogate.json")

SURR_PARAMS = {"objective": "binary", "learning_rate": 0.1, "num_leaves": 15,
               "min_data_in_leaf": 1, "seed": 7, "deterministic": True,
               "num_threads": 1, "verbose": -1}


# A cheap extractor owns a handful of boxes per network. Concentrating probes
# on a couple of /24s per pool is cheap — and exactly what a per-/24 budget
# punishes, because it poisons both the blocked and the allowed regions the
# clone is trying to learn.
CONCENTRATED = {"datacenter": ["172.16.0.7", "172.16.1.7"],
                "residential": ["10.1.0.7", "10.2.0.7"]}


def probe(configs, seed, run, concentrate=False):
    """Send one session per config; return [(cfg, verdict), ...].

    concentrate=True pins each probe to one of a couple of /24s in its own
    pool (the cheap attacker, few boxes per network). The fidelity ground
    truth uses concentrate=False, so its /24s are fresh and its verdicts are
    truthful even under the budget.
    """
    rng = random.Random(seed)
    personas = []
    for i, c in enumerate(configs):
        ip = CONCENTRATED[c["pool"]][i % 2] if concentrate else None
        personas.append(advlib.persona_for(c, rng, actor="round1_extract",
                                           cohort="extract", ip=ip))
    results = shopper.run_sessions(personas, seed=seed, run=run)
    # run_sessions preserves order, so result i is config i
    return [(configs[i], advlib.verdict(results[i])) for i in range(len(results))], results


def train_surrogate(pairs):
    X = np.array([advlib.encode(c) for c, _ in pairs], dtype=float)
    y = np.array([v for _, v in pairs], dtype=float)
    if len(set(y)) < 2:
        return None
    booster = lgb.train(SURR_PARAMS, lgb.Dataset(X, y), num_boost_round=60)
    return booster


def fidelity(booster, test_pairs):
    X = np.array([advlib.encode(c) for c, _ in test_pairs], dtype=float)
    pred = (booster.predict(X) >= 0.5).astype(int)
    truth = np.array([v for _, v in test_pairs])
    return float((pred == truth).mean())


def extract(queries=96, seed=61):
    """Probe the live oracle, fit a surrogate, measure fidelity. Returns stats."""
    rng = random.Random(seed)
    train_cfgs = [advlib.random_config(rng) for _ in range(queries)]
    train_pairs, train_results = probe(train_cfgs, seed, "round1_extract", concentrate=True)
    booster = train_surrogate(train_pairs)
    # Held-out ground truth: every config in the grid, one query each from a
    # FRESH spread of /24s, so these verdicts are truthful even under the
    # budget. Fidelity is the surrogate vs this clean boundary.
    test_pairs, _ = probe(advlib.all_configs(), seed + 1, "round1_fidtest", concentrate=False)
    fid = fidelity(booster, test_pairs) if booster else 0.0
    if booster:
        os.makedirs(DATA, exist_ok=True)
        booster.save_model(SURROGATE)
        with open(SURROGATE_META, "w") as fh:
            json.dump({"features": advlib.FEATURES, "queries": queries, "seed": seed}, fh)
    usd = sum(r["usd"] for r in train_results)
    blocked = sum(v for _, v in train_pairs)
    return {"queries": queries, "fidelity": fid, "usd": usd,
            "blocked_probes": blocked, "saved": bool(booster)}


def run(seed=61, queries=96, quiet=False):
    """checkpoint entrypoint: extract and stash stats on run.stats."""
    out = sys.stdout
    if quiet:
        sys.stdout = open(os.devnull, "w")
    try:
        stats = extract(queries=queries, seed=seed)
    finally:
        if quiet:
            sys.stdout.close()
            sys.stdout = out
    run.stats = stats
    return stats


def main():
    parser = argparse.ArgumentParser(description="Decision-based model extraction.")
    parser.add_argument("--queries", type=int, default=96)
    parser.add_argument("--seed", type=int, default=61)
    args = parser.parse_args()
    print(f"=== Round 1: extracting the decision oracle → {labnet.target()} ===")
    stats = extract(queries=args.queries, seed=args.seed)
    print(f"\n  probe queries: {stats['queries']}  (≈ ${stats['usd']:.2f} simulated, "
          f"{stats['blocked_probes']} blocked)")
    print(f"  surrogate fidelity on the full grid: {stats['fidelity']:.0%}")
    if stats["fidelity"] >= 0.9:
        print("  → a near-perfect clone. Round 2 can search it offline, for free.")
    else:
        print("  → the oracle is guarded: the clone is noisy and costs more to improve.")


if __name__ == "__main__":
    main()
