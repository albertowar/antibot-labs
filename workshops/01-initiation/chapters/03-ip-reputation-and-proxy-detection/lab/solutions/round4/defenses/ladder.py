"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 4.

Level k is enforced when k <= DEFENSE_LEVEL. `python tools/checkpoint.py --round 4` sets level 4.
"""

from . import rate_limit, blocklists, ip_reputation, trusted_proxy

LADDER = {
    0: [],
    1: [rate_limit.CHECK],
    2: [blocklists.CHECK],
    3: [ip_reputation.CHECK],
    4: [trusted_proxy.CHECK],
}
