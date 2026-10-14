"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 3.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 3` sets level 3.
Round 3 adds honeypot SKUs and catalogue coverage.
Order matters inside a level only for cost.
"""

from . import generic_layers
from . import breached_passwords, scalping_funnel, scrape_defense

LADDER = {
    0: [generic_layers.CHECK],
    1: [breached_passwords.CHECK],
    2: [scalping_funnel.CHECK],
    3: [scrape_defense.CHECK],
}
