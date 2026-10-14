"""
Round 1 attack: the humanized bot

Objective: beat model v1 without touching a single rule. The attacker has read the same papers you have:

  - residential-proxy exits in the US ($4/GB, simulated): each session on its own address
  - one carefully built stealth profile: a common Windows + NVIDIA + Chrome fingerprint with a New York
    locale, fully consistent
  - behaviour sampled from human-like distributions (curved mouse paths, jittered typing, scrolling),
    log-normal think times, browses a few products before the drop
  - never follows hidden links, never calls disallowed endpoints

Why it works: v1 was trained on honeypot-labeled bots. Nothing that looks like this session was ever
labeled "bot", so per-session features say "human". The model is only as good as its labels.

Its weakness (for Round 2): ONE profile reused for every session.

Expected results:
  - DEFENSE_LEVEL=1 -> nearly every purchase succeeds
  - DEFENSE_LEVEL=2 -> a few percent succeed (cohort features + cluster labels)

Run:
    python attacks/round1_humanized.py
"""

import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))

import labclient  # noqa: E402  (runs the labnet guard)
import shopper  # noqa: E402
from shopper import UA, Persona, accept_language, desktop_behavior, fingerprint, human_think  # noqa: E402

HISTORY_SEED, HISTORY_N = 20, 60       # the wave tools/simulate.py --wave appends to the training history
PROFILE_SEED = 42  # the one stealth profile the operator built


def stealth_profile():
    rng = random.Random(PROFILE_SEED)
    locale = shopper.LOCALES[1]  # America/New_York
    return fingerprint(rng, "win-nvidia", locale, "chrome_win"), locale


def personas(n=60, seed=0):
    rng = random.Random(seed + 1000)
    fp, locale = stealth_profile()
    exits = labclient.world_pool("resi_us")
    return [Persona(actor=f"bot:humanized:{i:03d}", persona="humanized", browser=("stealth",), ip=rng.choice(exits),
                    ua=UA["chrome_win"], accept_language=accept_language(locale[1]), fp=dict(fp),
                    behavior=desktop_behavior(rng), think=human_think(6.0), browse=rng.randint(1, 5), usd_per_gb=4.0)
            for i in range(n)]


def run(n=40, seed=21):
    """Run the attack; return one result per session (also used by tools/simulate.py)."""
    return shopper.run_sessions(personas(n, seed), seed=seed)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="the humanized bot.")
    parser.add_argument("--n", type=int, default=60, help="sessions")
    parser.add_argument("--seed", type=int, default=20)
    args = parser.parse_args()
    print(f"=== Round 1: humanized bot, one stealth profile, residential US -> {labclient.BASE_URL} ===")
    results = run(n=args.n, seed=args.seed)
    ok = sum(shopper.succeeded(r) for r in results)
    print(f"  purchases succeeded: {ok}/{len(results)}   proxy bill ~ ${sum(r['usd'] for r in results):.2f} (simulated)")
    scores = [r["score"] for r in results if r["score"] is not None]
    if scores:
        print(f"  X-Lab-Score on the purchase (the teaching-aid oracle): min {min(scores)}  max {max(scores)}")
    print(json.dumps(shopper.summarize_attack(results)))
