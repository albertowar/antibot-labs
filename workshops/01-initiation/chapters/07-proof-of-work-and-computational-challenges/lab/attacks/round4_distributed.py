"""
Chapter 7 — Round 4 Attack: be many small clients instead of one big one

Objective: adaptive difficulty prices *per client*. So never look like a
big client. Spread the 200 pages over 10 identities (10 simulated IPs, each
with its own cookie jar), and give each identity just one pass's worth of
pages. Each stays under the 30-requests-per-minute threshold and is charged
the base 16 bits.

In real life the identities are residential proxies (Chapter 3). Here they
are documentation addresses in one /24: 203.0.113.10 - 203.0.113.19.

Expected results:
  - DEFENSE_LEVEL<=3    → 200/200
  - DEFENSE_LEVEL=4     → 200/200, every solve at 16 bits: back to Round 3's price

Run:
    python attacks/round4_distributed.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _common import PAGES, Tally, client, close_pool, honest_pass, report, scrape  # noqa: E402

IDENTITIES = [f"203.0.113.{10 + i}" for i in range(10)]


def run():
    """Run the attack; return its scoreboard row (used by tools/checkpoint.py)."""
    tally = Tally("round4_distributed")
    per_identity = PAGES // len(IDENTITIES)
    try:
        for i, ip in enumerate(IDENTITIES):
            pages = range(i * per_identity + 1, (i + 1) * per_identity + 1)
            with client(ip) as c:
                before = tally.pages_ok
                scrape(c, tally, pages, get_pass=lambda: honest_pass(c, tally, parallel=True))
                if tally.pages_ok - before < len(pages):
                    break
    finally:
        close_pool()
    return tally.result()


if __name__ == "__main__":
    print("=== Round 4: 10 identities, one pass each ===")
    report(run())
