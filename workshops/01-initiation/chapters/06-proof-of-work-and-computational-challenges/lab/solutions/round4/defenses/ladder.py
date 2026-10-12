"""
The ladder: which checks run at which DEFENSE_LEVEL. Chapter 6 ships it pre-written:
you read each round's defense, then switch levels (DEFENSE_LEVEL=N, or
`python tools/checkpoint.py --round N`, which sets the level for you).

Level k is enforced when k <= DEFENSE_LEVEL. Cheapest and most certain first inside a level.
Edit a module under defenses/, save, and the store picks it up on the next request.

    L1  pow_gate       catalog pages need a solved challenge          (naive verifier)
    L2  (no new check) the same gate; pow_challenge now issues SIGNED challenges
    L3  pow_budget     a pass is worth 20 requests / 120 s, bound to IP + User-Agent;
                       challenges become single-use
    L4  pow_adaptive   the difficulty follows the client's request rate

Fell behind? `python tools/checkpoint.py --round N --catch-up` reinstalls the reference
`defenses/ladder.py` and `defenses/policy.py` from solutions/round1..N.
"""

from . import pow_adaptive, pow_budget, pow_gate

LADDER = {
    0: [],
    1: [pow_gate.CHECK],
    2: [],
    3: [pow_budget.CHECK],
    4: [pow_adaptive.CHECK],
}
