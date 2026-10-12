"""
The ladder: which checks run at which DEFENSE_LEVEL. (YOUR FILE in wire-it labs.)

    LADDER = {
        0: [],                                  # baseline, always on (this workshop's baseline)
        1: [rate_limit.CHECK, headers.CHECK],   # Round 1 adds these
        2: [ip_reputation.CHECK],               # Round 2 adds these on top
    }

Level k is enforced when k <= DEFENSE_LEVEL. Cheapest and most certain first
inside a level: a hard verdict stops the gate before the slower checks run.

Change it, save, and the store picks it up on the next request (LAB_RELOAD=1).
Fell behind? `python tools/checkpoint.py --round N --catch-up` installs the
reference version for round N.
"""

# from . import example_check          # 1. import the check module
LADDER = {
    0: [],
    # 1: [example_check.CHECK],        # 2. wire it into a level
}
