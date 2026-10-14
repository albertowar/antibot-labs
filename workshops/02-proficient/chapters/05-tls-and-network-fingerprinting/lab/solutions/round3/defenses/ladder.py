"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 3.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 3` sets level 3.
Round 3 adds the HTTP/2 preface check; every level below it stays on.
"""

from . import ja4_denylist, tls_family, h2_fingerprint

LADDER = {
    0: [],
    1: [ja4_denylist.CHECK],
    2: [tls_family.CHECK],
    3: [h2_fingerprint.CHECK],
}
