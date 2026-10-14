"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 1.

Level k is enforced when k <= DEFENSE_LEVEL. `python tools/checkpoint.py --round 1` sets level 1.
Round 1's only layer watches; it never blocks.
"""

from . import flood_monitor

LADDER = {
    0: [],
    1: [flood_monitor.CHECK],
}
