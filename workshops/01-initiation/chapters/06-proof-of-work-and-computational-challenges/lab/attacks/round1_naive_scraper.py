"""
Chapter 6, Round 1 attack (a): the scraper that has never heard of proof of work.

Objective: fetch all 120 product records from /api/products/<sku> with a plain HTTP client,
no JavaScript. The gate answers the first request with `challenge_required`; this scraper
does not know what to do with that, so it stops.

Expected:
  DEFENSE_LEVEL=0     120/120
  DEFENSE_LEVEL>=1    0/120   (X-Lab-Signals: pow:no_pass)

This is also exactly what a real user with JavaScript disabled looks like. Keep that in
mind when you read the shoppers table: the `no_js` shopper is stopped by the same check.

    python attacks/round1_naive_scraper.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
from pow_client import SKUS, Tally, bot, finish, scrape  # noqa: E402


def run():
    tally = Tally("round1_naive_scraper")
    scrape(bot("pow-naive", index=1), tally, SKUS, get_pass=lambda payload: False)
    return tally.result()


if __name__ == "__main__":
    print("=== Round 1a: naive scraper, no proof of work ===")
    finish(run())
