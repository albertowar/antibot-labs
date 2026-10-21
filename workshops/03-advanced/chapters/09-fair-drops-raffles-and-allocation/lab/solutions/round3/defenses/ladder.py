"""
The ladder: which checks run at which DEFENSE_LEVEL (reference, as it stands after Round 3).
"""

from . import scalping_funnel
from . import raffle_basics
from . import eligibility
from . import entity_resolution

LADDER = {
    0: [scalping_funnel.CHECK],
    1: [raffle_basics.CHECK],
    2: [eligibility.CHECK],
    3: [entity_resolution.CHECK],
}
