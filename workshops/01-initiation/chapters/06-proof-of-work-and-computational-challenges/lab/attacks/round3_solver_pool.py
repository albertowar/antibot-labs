"""
Chapter 6, Round 3 attack: just pay, on every core.

Objective: stop cheating and start paying. Every time the gate asks, take the challenge from
its 403 and solve it on all cores at once (worker i tries counters i, i+n, i+2n, ...). Each
solve buys POW_PASS_BUDGET products, so 120 products cost about 6 solves.

What to look at is not the success rate (it will be 100%) but the *price*: CPU-seconds and
dollars per 1,000 pages. Compare it with the ~$1 per 1,000 that a CAPTCHA-solving farm
charges (Chapter 5).

Expected:
  DEFENSE_LEVEL<=2    120/120, one solve
  DEFENSE_LEVEL=3     120/120, ~6 solves at 16 bits
  DEFENSE_LEVEL=4     120/120, but the difficulty climbs to 20 and 22 bits as this IP's
                      request rate rises: the price goes up 16-64x (Round 4)

    python attacks/round3_solver_pool.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
from pow_client import SKUS, Tally, bot, close_pool, finish, honest_pass, scrape  # noqa: E402


def run():
    tally = Tally("round3_solver_pool")
    try:
        c = bot("pow-pool", index=5)
        scrape(c, tally, SKUS, get_pass=lambda payload: honest_pass(c, tally, payload, parallel=True))
    finally:
        close_pool()
    return tally.result()


if __name__ == "__main__":
    print("=== Round 3: solver pool, pay for every pass ===")
    finish(run())
