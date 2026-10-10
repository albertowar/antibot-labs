"""
Chapter 7 — Round 3 Attack: just pay, on every core

Objective: stop cheating and start paying. Every time the gate asks, fetch
a fresh challenge and solve it on all cores at once (multiprocessing,
worker i tries counters i, i+n, i+2n, ...). Each solve buys PASS_BUDGET
pages, so 200 pages cost about 10 solves.

What to look at is not the success rate (it will be 100%) but the *price*:
CPU-seconds and dollars per 1,000 pages. Compare it with the ~$1 per 1,000
that a CAPTCHA-solving farm charges (Chapter 6).

Expected results:
  - DEFENSE_LEVEL<=2    → 200/200, one solve
  - DEFENSE_LEVEL=3     → 200/200, ~10 solves at 16 bits
  - DEFENSE_LEVEL=4     → 200/200, but the difficulty climbs to 20 and 22 bits as
                          this IP's request rate rises: the cost multiplies (Round 4)

Run:
    python attacks/round3_solver_pool.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _common import PAGES, Tally, client, close_pool, honest_pass, report, scrape  # noqa: E402


def run():
    """Run the attack; return its scoreboard row (used by tools/checkpoint.py)."""
    tally = Tally("round3_solver_pool")
    try:
        with client() as c:
            scrape(c, tally, range(1, PAGES + 1),
                   get_pass=lambda: honest_pass(c, tally, parallel=True))
    finally:
        close_pool()
    return tally.result()


if __name__ == "__main__":
    print("=== Round 3: solver pool, pay for every pass ===")
    report(run())
