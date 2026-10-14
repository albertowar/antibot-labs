"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 2.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 2` sets level 2.
Round 2 adds per-cohort failure and unknown-account ratios on top of the login throttle.
"""

from . import login_throttle, population_signals

LADDER = {
    0: [],
    1: [login_throttle.CHECK],
    2: [population_signals.CHECK],
}
