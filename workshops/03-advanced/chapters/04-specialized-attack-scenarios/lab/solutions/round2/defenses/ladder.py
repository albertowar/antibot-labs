"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 2.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 2` sets level 2.
Round 2 adds funnel integrity and one unit per device.
Order matters inside a level only for cost.
"""

from . import generic_layers
from . import breached_passwords, scalping_funnel

LADDER = {
    0: [generic_layers.CHECK],
    1: [breached_passwords.CHECK],
    2: [scalping_funnel.CHECK],
}
