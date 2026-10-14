"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 3.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 3` sets level 3.
Round 3 adds the breached-password step-up and closes the account-recovery oracle.
"""

from . import breached_passwords, login_throttle, oracles, population_signals

LADDER = {
    0: [],
    1: [login_throttle.CHECK],
    2: [population_signals.CHECK],
    3: [breached_passwords.CHECK, oracles.CHECK],
}
