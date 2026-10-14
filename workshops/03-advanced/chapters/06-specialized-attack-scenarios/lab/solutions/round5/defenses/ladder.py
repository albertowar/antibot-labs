"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 5.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 5` sets level 5.
Round 5 adds GIVT hard filters and the SIVT engagement funnel.
Order matters inside a level only for cost.
"""

from . import generic_layers
from . import account_cluster, breached_passwords, ivt_scoring, scalping_funnel, scrape_defense

LADDER = {
    0: [generic_layers.CHECK],
    1: [breached_passwords.CHECK],
    2: [scalping_funnel.CHECK],
    3: [scrape_defense.CHECK],
    4: [account_cluster.CHECK],
    5: [ivt_scoring.CHECK],
}
