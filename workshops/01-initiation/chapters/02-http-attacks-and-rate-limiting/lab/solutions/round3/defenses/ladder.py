"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 3.

Level k is enforced when k <= DEFENSE_LEVEL. `python tools/checkpoint.py --round 3` sets level 3.

Round 3 adds the token bucket on top of the fixed window. The two stack: a request must
satisfy both, and the strictest answer wins. The bucket is what Chapter 3 and the Chapter 9
capstone build on, so the reference ladder wires `rate_limit`.

To try the boundary-free counter instead, swap `rate_limit` for `sliding_window` at level 3:

    from . import sliding_window
    3: [sliding_window.CHECK],

Both hold the round's expectations. Run each against the boundary attack and the shoppers and
compare the scoreboard: the bucket grants a clean burst, the sliding window a flatter rate.
"""

from . import fixed_window, flood_monitor, rate_limit

LADDER = {
    0: [],
    1: [flood_monitor.CHECK],
    2: [fixed_window.CHECK],
    3: [rate_limit.CHECK],
}
