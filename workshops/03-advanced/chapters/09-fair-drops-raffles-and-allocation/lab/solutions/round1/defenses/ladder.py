"""
The ladder: which checks run at which DEFENSE_LEVEL (reference, as it stands after Round 1).
"""

from . import scalping_funnel
from . import raffle_basics

LADDER = {
    0: [scalping_funnel.CHECK],
    1: [raffle_basics.CHECK],
}
