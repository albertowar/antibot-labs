"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 2.

Level k is enforced when k <= DEFENSE_LEVEL. `python tools/checkpoint.py --round 2` sets level 2.
The monitor from Round 1 keeps logging under the fixed window that now blocks.
"""

from . import fixed_window, flood_monitor

LADDER = {
    0: [],
    1: [flood_monitor.CHECK],
    2: [fixed_window.CHECK],
}
