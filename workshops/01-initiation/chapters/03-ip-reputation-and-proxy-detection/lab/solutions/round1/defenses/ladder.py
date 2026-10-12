"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 1.

Level k is enforced when k <= DEFENSE_LEVEL. `python tools/checkpoint.py --round 1` sets level 1.
"""

from . import rate_limit

LADDER = {
    0: [],
    1: [rate_limit.CHECK],
}
