"""
Chapter 6, Round 4 attack: be many small clients instead of one big one.

Objective: adaptive difficulty prices *per client*. So never look like a big client. Spread
the 120 products over 10 identities (10 rented IPs, each with its own cookie jar) and give
each identity less than one pass's worth. Each stays under the first rate threshold and is
charged the base 16 bits.

In real life the identities are residential proxies (Chapter 3). Here they are ten
addresses from the `cloud_vm` pool, all in one /24 (203.0.113.0/24): remember that for the
`rate_key` TODO in defenses/pow_adaptive.py.

Expected:
  DEFENSE_LEVEL<=3    120/120
  DEFENSE_LEVEL=4     120/120, every solve at 16 bits: back to Round 3's price

    python attacks/round4_distributed.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
from pow_client import SKUS, Tally, bot, close_pool, finish, honest_pass, scrape  # noqa: E402

IDENTITIES = 10


def run():
    tally = Tally("round4_distributed")
    per_identity = len(SKUS) // IDENTITIES
    try:
        for i in range(IDENTITIES):
            c = bot("pow-farm", index=10 + i)
            skus = SKUS[i * per_identity:(i + 1) * per_identity]
            before = tally.pages_ok
            scrape(c, tally, skus, get_pass=lambda payload, c=c: honest_pass(c, tally, payload, parallel=True))
            if tally.pages_ok - before < len(skus):
                break
    finally:
        close_pool()
    return tally.result()


if __name__ == "__main__":
    print("=== Round 4: 10 identities, one pass each ===")
    finish(run())
