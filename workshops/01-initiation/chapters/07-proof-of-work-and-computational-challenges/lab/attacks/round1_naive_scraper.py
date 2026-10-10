"""
Chapter 7 — Round 1 Attack (a): the scraper that has never heard of PoW

Objective: walk all 200 catalog pages with plain httpx, no JavaScript.

Expected results:
  - DEFENSE_LEVEL=0     → 200/200 pages
  - DEFENSE_LEVEL>=1    → 0/200, "no PoW pass: solve /pow/challenge first"

This is also exactly what a real user with JavaScript disabled looks like.
Keep that in mind when you read the false-positive line of the checkpoint.

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=0 python app.py
Then run:
    python attacks/round1_naive_scraper.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _common import PAGES, Tally, client, report, scrape  # noqa: E402


def run():
    """Run the attack; return its scoreboard row (used by tools/checkpoint.py)."""
    tally = Tally("round1_naive_scraper")
    with client() as c:
        scrape(c, tally, range(1, PAGES + 1), get_pass=lambda: False)
    return tally.result()


if __name__ == "__main__":
    print("=== Round 1a: naive scraper, no PoW ===")
    report(run())
