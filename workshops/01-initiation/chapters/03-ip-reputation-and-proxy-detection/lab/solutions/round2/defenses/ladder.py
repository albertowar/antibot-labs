"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 2.

Level k is enforced when k <= DEFENSE_LEVEL. `python tools/checkpoint.py --round 2` sets level 2.
"""

from . import rate_limit, blocklists

LADDER = {
    0: [],
    1: [rate_limit.CHECK],
    2: [blocklists.CHECK],
}
