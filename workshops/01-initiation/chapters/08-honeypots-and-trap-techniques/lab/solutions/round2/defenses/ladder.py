"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 2.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N` sets level N.
Round 2 adds the timing token. (The honeypot itself is hardened in form_traps.py.)
"""

from . import form_traps

LADDER = {
    0: [],
    1: [form_traps.HONEYPOT_CHECK],
    2: [form_traps.TIMING_CHECK],
}
