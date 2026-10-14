"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 1.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 1` sets level 1.
Round 1 adds the login throttle (per-IP velocity and per-account lockout).
"""

from . import login_throttle

LADDER = {
    0: [],
    1: [login_throttle.CHECK],
}
