"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 1.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 1` sets level 1.
Round 1 adds a correct but breached password needs an emailed code.
Order matters inside a level only for cost.
"""

from . import generic_layers
from . import breached_passwords

LADDER = {
    0: [generic_layers.CHECK],
    1: [breached_passwords.CHECK],
}
