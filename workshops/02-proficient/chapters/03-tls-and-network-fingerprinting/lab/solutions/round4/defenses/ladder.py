"""
The ladder: which checks run at which DEFENSE_LEVEL. Reference version for Round 4.

Level k is enforced when k <= DEFENSE_LEVEL; `python tools/checkpoint.py --round 4` sets level 4.
Round 4 adds the browser proof; every level below it stays on.
"""

from . import ja4_denylist, tls_family, h2_fingerprint, browser_proof

LADDER = {
    0: [],
    1: [ja4_denylist.CHECK],
    2: [tls_family.CHECK],
    3: [h2_fingerprint.CHECK],
    4: [browser_proof.CHECK],
}
