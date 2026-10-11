"""
W4 Chapter 7 — Round 3 Attack: make the analyst too expensive to run

No injection, no evasion. Just volume with novelty. Each session is one or
two requests with a unique, multi-kilobyte User-Agent and Accept-Language of
random tokens. There is nothing to buy here: the goal is to make a
per-session LLM pipeline either spend a fortune in tokens or fall so far
behind that real sessions never get triaged (OWASP LLM10, Unbounded
Consumption).

The novelty matters: identical junk would collapse into one cluster. Random
junk is meant to defeat naive de-duplication. The Round 3 defense answers it
with structural clustering (shape, not bytes) plus a pre-filter and a token
budget, so the flood collapses to a handful of representatives.

Sessions default to the "touch" journey (no checkout): a flood does not need
to buy anything to cost you triage.

Run:
    python attacks/round3_token_flood.py --n 400
"""

import argparse
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import labnet  # noqa: E402
import shopper  # noqa: E402
from shopper import Persona, fixed_think  # noqa: E402

WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima "
         "mike november oscar papa quebec romeo sierra tango").split()


def _salad(rng, n):
    return " ".join(rng.choice(WORDS) + str(rng.randint(100, 999)) for _ in range(n))


def flooder(rng):
    ip, _ = labnet.Pool("datacenter", rng=rng).next()
    # 1.5–3 KB of unique User-Agent, plus a long Accept-Language.
    ua = "Mozilla/5.0 " + _salad(rng, rng.randint(180, 360))
    lang = _salad(rng, rng.randint(20, 40))
    return Persona(actor="round3_token_flood", cohort="flood", is_bot=True, ip=ip,
                   user_agent=ua[:3000], headers={"Accept-Language": lang[:1500]},
                   think=fixed_think(0.3), journey="touch", loads_assets=False,
                   payload="flood", usd_per_gb=0.10,
                   config={"ua_bytes": len(ua)})


def personas(n=400, seed=0):
    rng = random.Random(seed + 703)
    return [flooder(rng) for _ in range(n)]


def run(n=400, seed=23):
    # Cap workers: thousands of tiny writes to one SQLite file want a short queue.
    return shopper.run_sessions(personas(n, seed), seed=seed, workers=8, run="round3_token_flood")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--seed", type=int, default=23)
    args = ap.parse_args()
    print(f"=== Round 3: token flood ({args.n} sessions) → {labnet.target()} ===")
    results = run(args.n, args.seed)
    print(f"  {len(results)} sessions sent, each with a unique multi-KB User-Agent.")
    print("  Naive triage:     python defenses/triage.py --since-run round3_token_flood --hardened --token-budget 40000")
    print("  Defended triage:  add --prefilter --cluster")
