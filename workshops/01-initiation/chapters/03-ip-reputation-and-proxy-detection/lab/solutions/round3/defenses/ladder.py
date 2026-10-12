"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 3.

Level k is enforced when k <= DEFENSE_LEVEL. `python tools/checkpoint.py --round 3` sets level 3.
"""

from . import rate_limit, blocklists, ip_reputation

LADDER = {
    0: [],
    1: [rate_limit.CHECK],
    2: [blocklists.CHECK],
    3: [ip_reputation.CHECK],
}
