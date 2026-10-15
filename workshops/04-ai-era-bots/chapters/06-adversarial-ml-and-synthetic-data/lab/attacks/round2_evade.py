"""
Round 2 attack: evade the model with its own clone

Round 1 handed the attacker a surrogate: a private copy of the defender's decision boundary (the patient
extractor's, attacks/round1_extract.py --patient). Now it uses it the way an attacker actually would:
offline, for free, with no further queries to tip the defender off.

We enumerate the knob grid (attacks/advlib.py), ask the SURROGATE which configs it predicts as "allowed",
and pick the cheapest one. Because every persona we build is internally consistent (a real device shape from
the fingerprint shop, a different exit for every session), this is a *feature-space evasion under
realizability constraints*: we are not inventing impossible devices to fool a fingerprint check, we are
choosing a genuinely buildable session that lands on the human side of the boundary.

Then we replay that single config against the REAL store. If the surrogate was faithful, the evasion
transfers (Papernot et al., 2017).

  - vs the baseline model v2 (DEFENSE_LEVEL=1)  -> every session gets through
  - vs the robust model v3 (DEFENSE_LEVEL=2)    -> adversarial training + monotone constraints close it

The red team's own sessions are also the defender's best training data: `python tools/simulate.py --wave
round2_evade` runs this attack as a wave and hands the sessions to the defender (capture() below), who
labels them bot because they are the red team's own. That is the input of defenses/robust_train.py.

Run (store up; run Round 1 with --patient first so a surrogate exists):
    python attacks/round2_evade.py
    python tools/simulate.py --wave round2_evade          # the same attack, captured as adversarial examples
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
from round1_extract import surrogate_path  # noqa: E402

HISTORY_N, HISTORY_SEED = 40, 72       # the wave tools/simulate.py --wave appends to the training history
ADVERSARIAL = os.path.join(HERE, "..", "data", "adversarial.parquet")


def load_surrogate():
    path = surrogate_path(patient=True)
    if not os.path.exists(path):
        sys.exit("No surrogate yet. Run: python attacks/round1_extract.py --patient")
    return lgb.Booster(model_file=path)


def best_config(booster):
    """The cheapest config the surrogate predicts as 'allowed' (lowest refusal probability)."""
    configs = advlib.all_configs()
    risk = booster.predict(np.array([advlib.encode(c) for c in configs], dtype=float))
    order = sorted(range(len(configs)), key=lambda i: (round(float(risk[i]), 4), advlib.cost_rank(configs[i])))
    return configs[order[0]], float(risk[order[0]])


def personas(n=40, seed=0):
    cfg, _ = best_config(load_surrogate())
    rng = random.Random(seed + 2000)
    return [advlib.persona_for(cfg, rng, i, "evade") for i in range(n)]


def run(n=HISTORY_N, seed=HISTORY_SEED):
    return shopper.run_sessions(personas(n, seed), seed=seed)


def capture(results):
    """Red-team bookkeeping: save the features of OUR OWN evasive sessions, labelled bot.

    This is not ground truth from the simulator. It is what a defender's red team hands to training after
    confirming the sessions were theirs: the session ids are the red team's own. Features are computed
    exactly as for training (features.build_dataset over the history of the stages so far), and
    defenses/robust_train.py folds them back in as confirmed bots. Returns how many were captured.
    """
    sys.path.insert(0, os.path.join(HERE, ".."))
    from defenses import waves
    from defenses.features import build_dataset
    sids = {r["sid"] for r in results if r.get("sid")}
    df = build_dataset(waves.for_stage("robust"), with_cohort=True)
    mine = df[df["sid"].isin(sids)].copy() if not df.empty else df
    if mine.empty:
        return 0
    mine["label"] = 1
    os.makedirs(os.path.dirname(ADVERSARIAL), exist_ok=True)
    mine.to_parquet(ADVERSARIAL, index=False)
    return len(mine)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Transfer evasion from the surrogate.")
    parser.add_argument("--n", type=int, default=60)
    parser.add_argument("--seed", type=int, default=70)
    args = parser.parse_args()
    cfg, risk = best_config(load_surrogate())
    print(f"=== Round 2: the surrogate picks {' '.join(f'{k}={cfg[k]}' for k in advlib.FEATURES)} -> {labclient.BASE_URL} ===")
    print(f"  the clone predicts refusal probability {risk:.2f}")
    results = run(args.n, args.seed)
    ok = sum(shopper.succeeded(r) for r in results)
    print(f"  replayed live: {ok}/{len(results)} purchases confirmed  (~${sum(r['usd'] for r in results):.2f} simulated)")
    print(json.dumps(shopper.summarize_attack(results, config=cfg)))
