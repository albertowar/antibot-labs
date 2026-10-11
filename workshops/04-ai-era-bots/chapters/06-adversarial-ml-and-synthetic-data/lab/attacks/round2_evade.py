"""
W4 Ch6 — Round 2 Attack: evade the model with its own clone (Section 6.4)

Round 1 handed us a surrogate: a private copy of the defender's decision
boundary. Now we use it the way an attacker actually would — offline, for
free, with no further queries to tip the defender off.

We enumerate the knob grid (attacks/advlib.py), ask the SURROGATE which
configs it predicts as "allowed", and pick the cheapest one. Because every
persona we build is internally consistent (a real device shape), this is a
*feature-space evasion under realizability constraints*: we are not
inventing impossible devices to fool a fingerprint check, we are choosing a
genuinely buildable session that lands on the human side of the boundary.

Then we replay that single config against the REAL site. If the surrogate
was faithful, the evasion transfers (Papernot et al., 2017).

  - vs the base model v2 (DEFENSE_LEVEL=2, stub robust_train) → most get through
  - vs the robust model v3 (adversarial training + monotone constraints)
    → the cheap evasions are closed; what is left is expensive or detectable

Run (demo site up at DEFENSE_LEVEL=2; run Round 1 first so a surrogate exists):
    python attacks/round2_evade.py
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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "defenses"))

import advlib  # noqa: E402
import labnet  # noqa: E402
import shopper  # noqa: E402
from round1_extract import SURROGATE, SURROGATE_META  # noqa: E402


def load_surrogate():
    if not os.path.exists(SURROGATE):
        sys.exit("No surrogate yet. Run attacks/round1_extract.py (or checkpoint --round 1).")
    with open(SURROGATE_META) as fh:
        json.load(fh)
    return lgb.Booster(model_file=SURROGATE)


ADVERSARIAL = os.path.join(os.path.dirname(__file__), "..", "data", "adversarial.parquet")


def capture(results):
    """Red-team bookkeeping: save the server-side features of OUR OWN evasive
    sessions, labelled bot. This is not ground truth from the simulator — it
    is what a defender's red team would hand to training after confirming the
    sessions were theirs. Round 2's defense (defenses/robust_train.py) feeds
    these back as adversarial examples.
    """
    from features import build_dataset
    from store import make_engine
    sids = {r["sid"] for r in results if r.get("sid")}
    if not sids:
        return 0
    with make_engine().connect() as conn:
        df = build_dataset(conn, with_cohort=True)
    mine = df[df["sid"].isin(sids)].copy()
    if mine.empty:
        return 0
    mine["label"] = 1
    os.makedirs(os.path.dirname(ADVERSARIAL), exist_ok=True)
    mine.to_parquet(ADVERSARIAL, index=False)
    return len(mine)


def best_config(booster):
    """The cheapest config the surrogate predicts as 'allowed' (lowest block prob)."""
    configs = advlib.all_configs()
    X = np.array([advlib.encode(c) for c in configs], dtype=float)
    risk = booster.predict(X)
    order = sorted(range(len(configs)),
                   key=lambda i: (round(float(risk[i]), 4), advlib.cost_rank(configs[i])))
    return configs[order[0]], float(risk[order[0]])


def personas(n=40, seed=0):
    booster = load_surrogate()
    cfg, _risk = best_config(booster)
    rng = random.Random(seed + 2000)
    return [advlib.persona_for(cfg, rng, actor="round2_evade", cohort="evade")
            for _ in range(n)], cfg


def run(n=40, seed=72, quiet=False):
    out = sys.stdout
    if quiet:
        sys.stdout = open(os.devnull, "w")
    try:
        people, cfg = personas(n, seed)
        results = shopper.run_sessions(people, seed=seed, run="round2_evade")
        n_captured = capture(results)
    finally:
        if quiet:
            sys.stdout.close()
            sys.stdout = out
    run.stats = {"config": cfg, "ok": sum(shopper.succeeded(r) for r in results),
                 "n": len(results), "usd": sum(r["usd"] for r in results),
                 "captured": n_captured}
    return results


def main():
    parser = argparse.ArgumentParser(description="Transfer evasion from the surrogate.")
    parser.add_argument("--n", type=int, default=60)
    parser.add_argument("--seed", type=int, default=70)
    args = parser.parse_args()
    booster = load_surrogate()
    cfg, risk = best_config(booster)
    print(f"=== Round 2: surrogate picks {advlib.cost_rank(cfg)} → {labnet.target()} ===")
    print("  chosen config: " + " ".join(f"{k}={cfg[k]}" for k in advlib.FEATURES))
    print(f"  surrogate predicts block probability {risk:.2f}")
    results = run(n=args.n, seed=args.seed)
    s = run.stats
    print(f"\n  replayed live: {s['ok']}/{s['n']} checkouts confirmed  "
          f"(≈ ${s['usd']:.2f} simulated)")


if __name__ == "__main__":
    main()
