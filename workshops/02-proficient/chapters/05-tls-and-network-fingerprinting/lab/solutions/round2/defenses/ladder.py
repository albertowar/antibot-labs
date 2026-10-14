"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 2.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 2` sets level 2.
Round 2 adds the UA-to-TLS-family consistency check; every level below it stays on.
"""

from . import ja4_denylist, tls_family

LADDER = {
    0: [],
    1: [ja4_denylist.CHECK],
    2: [tls_family.CHECK],
}
