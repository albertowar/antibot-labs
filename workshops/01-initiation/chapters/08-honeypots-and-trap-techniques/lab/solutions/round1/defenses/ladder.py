"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 1.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N` sets level N.
Round 1 guards the signup form with the textbook honeypot.
"""

from . import form_traps

LADDER = {
    0: [],
    1: [form_traps.HONEYPOT_CHECK],
}
