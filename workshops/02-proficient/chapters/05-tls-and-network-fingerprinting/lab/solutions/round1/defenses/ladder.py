"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 1.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 1` sets level 1.
Round 1 adds the JA4 denylist of HTTP libraries; every level below it stays on.
"""

from . import ja4_denylist

LADDER = {
    0: [],
    1: [ja4_denylist.CHECK],
}
