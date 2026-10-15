"""
Round 1 attack: steal the model

The defender's model is now an ASSET. You do not have its file, but you can query it: every purchase
returns a verdict (allowed or refused), and the store has to give you that verdict because it has to act
on it. One bit per query. Tramer et al. (2016) showed that one bit is enough to clone a model through its
prediction API; Papernot et al. (2017) showed the clone transfers.

This is *decision-based* model extraction. We send probe sessions across the knob space
(attacks/advlib.py), read the one-bit verdict, and fit a SURROGATE on (knobs -> verdict). The surrogate is
the attacker's private, offline copy of the defender's decision boundary. Round 2 uses it to find an
evasion without ever touching the real model again.

The metric is FIDELITY: on a held-out set (every config in the 64-point grid, one probe each, from
addresses the extractor has never used), how often does the surrogate agree with the real model?

Two extractors, because the guard is only as good as the attacker is lazy:

  (default)   the CHEAP extractor owns a few boxes at each provider (advlib.CHEAP_BOXES) and sends all
              its probes from them. Cheap, and exactly what a per-address query budget punishes.
  --patient   rotates through every exit its providers sell: the same probes, spread thin. A per-address
              budget never triggers. It saves the surrogate Round 2 attacks with.

  - no guard (the stub oracle_guard)  -> fidelity ~100% for both
  - per-address budget (the solution) -> the cheap extractor's clone collapses; the patient one is untouched

Run (store up at DEFENSE_LEVEL=1 or higher):
    python attacks/round1_extract.py
    python attacks/round1_extract.py --patient
"""

import argparse
import json
import os
import random
import sys

import lightgbm as lgb
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import advlib  # noqa: E402
import labclient  # noqa: E402
import shopper  # noqa: E402

DATA = os.path.join(HERE, "..", "data")
QUERIES = 160
SURR_PARAMS = {"objective": "binary", "learning_rate": 0.1, "num_leaves": 15, "min_data_in_leaf": 1,
               "seed": 7, "deterministic": True, "num_threads": 1, "verbose": -1}


def surrogate_path(patient):
    return os.path.join(DATA, "surrogate_patient.txt" if patient else "surrogate_cheap.txt")


def probe(configs, seed, mode):
    """Send one session per config; return [(cfg, verdict)] and the raw results.

    mode "cheap"    pin each probe to one of the extractor's own boxes at its provider
    mode "patient"  a different exit for every probe (a rotating pool)
    mode "fresh"    an address the extractor has never used: the held-out grid, answered truthfully
    """
    rng = random.Random(seed)
    people = []
    for i, c in enumerate(configs):
        boxes = advlib.cheap_boxes(c["pool"])
        ip = {"cheap": boxes[i % len(boxes)], "patient": None,
              "fresh": rng.choice(advlib.fresh_addresses(c["pool"]))}[mode]
        people.append(advlib.persona_for(c, rng, i, f"extract_{mode}", ip=ip))
    results = shopper.run_sessions(people, seed=seed)
    # run_sessions preserves order, so result i is config i
    return [(configs[i], advlib.verdict(results[i])) for i in range(len(results))], results


def train_surrogate(pairs):
    X = np.array([advlib.encode(c) for c, _ in pairs], dtype=float)
    y = np.array([v for _, v in pairs], dtype=float)
    if len(set(y)) < 2:
        return None, float(y[0]) if len(y) else 1.0     # one class seen: the clone is a constant
    return lgb.train(SURR_PARAMS, lgb.Dataset(X, y), num_boost_round=60), None


def predict(booster, constant, configs):
    if booster is None:
        return np.full(len(configs), int(constant >= 0.5))
    X = np.array([advlib.encode(c) for c in configs], dtype=float)
    return (booster.predict(X) >= 0.5).astype(int)


def extract(queries=QUERIES, seed=61, patient=False):
    """Probe the live oracle, fit a surrogate, measure fidelity on the held-out grid. Returns stats."""
    rng = random.Random(seed)
    train_cfgs = [advlib.random_config(rng) for _ in range(queries)]
    train_pairs, train_results = probe(train_cfgs, seed, "patient" if patient else "cheap")
    booster, constant = train_surrogate(train_pairs)
    grid = advlib.all_configs()
    test_pairs, _ = probe(grid, seed + 1, "fresh")
    pred = predict(booster, constant, grid)
    truth = np.array([v for _, v in test_pairs])
    allowed = truth == 0
    stats = {"fidelity": round(float((pred == truth).mean()), 3),
             # what the next round needs: of the configs that really pass, how many does the clone know?
             "allowed_found": round(float((pred[allowed] == 0).mean()), 3) if allowed.any() else 0.0,
             "allowed_in_grid": int(allowed.sum()), "queries": queries,
             "blocked_probes": int(sum(v for _, v in train_pairs)),
             "usd": round(sum(r["usd"] for r in train_results), 2)}
    if booster is not None:
        os.makedirs(DATA, exist_ok=True)
        booster.save_model(surrogate_path(patient))
        with open(surrogate_path(patient).replace(".txt", ".json"), "w") as fh:
            json.dump({"features": advlib.FEATURES, "queries": queries, "seed": seed, "patient": patient}, fh)
    stats["saved"] = booster is not None
    return stats


def main():
    parser = argparse.ArgumentParser(description="Decision-based model extraction.")
    parser.add_argument("--queries", type=int, default=QUERIES)
    parser.add_argument("--seed", type=int, default=61)
    parser.add_argument("--patient", action="store_true", help="rotate exits instead of using a few boxes")
    args = parser.parse_args()
    who = "patient (rotating exits)" if args.patient else "cheap (a few boxes per provider)"
    print(f"=== Round 1: extracting the decision oracle, {who} -> {labclient.BASE_URL} ===")
    stats = extract(args.queries, args.seed, args.patient)
    print(f"\n  probe queries: {stats['queries']}  (~${stats['usd']:.2f} simulated), {stats['blocked_probes']} refused")
    print(f"  surrogate fidelity on the full grid: {stats['fidelity']:.0%}")
    print(f"  of the {stats['allowed_in_grid']} configs that really get through, the clone knows {stats['allowed_found']:.0%}")
    if stats["allowed_found"] >= 0.9:
        print("  -> a near-perfect clone. Round 2 can search it offline, for free.")
    else:
        print("  -> the oracle is guarded: the clone is noisy and costs more to improve.")
    print(json.dumps({"attempted": stats["queries"], "succeeded": stats["queries"] - stats["blocked_probes"], **stats}))


if __name__ == "__main__":
    main()
