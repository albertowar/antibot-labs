"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 4.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 4` sets level 4.
Round 4 adds disposable domains, egress velocity and device clusters.
Order matters inside a level only for cost.
"""

from . import generic_layers
from . import account_cluster, breached_passwords, scalping_funnel, scrape_defense

LADDER = {
    0: [generic_layers.CHECK],
    1: [breached_passwords.CHECK],
    2: [scalping_funnel.CHECK],
    3: [scrape_defense.CHECK],
    4: [account_cluster.CHECK],
}
