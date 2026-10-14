"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 3.

Level k is enforced when k <= DEFENSE_LEVEL, and `python tools/checkpoint.py --round N` sets level N.
Round 3 adds the crawl traps.
"""

from . import crawl_traps, form_traps

LADDER = {
    0: [],
    1: [form_traps.HONEYPOT_CHECK],
    2: [form_traps.TIMING_CHECK],
    3: [crawl_traps.CHECK],
}
