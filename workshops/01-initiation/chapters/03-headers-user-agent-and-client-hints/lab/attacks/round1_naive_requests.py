"""
Chapter 3, Round 1 attack: the naive scraper.

Objective: scrape the catalog (five pages of /api/products) with python-requests defaults. This is what
most first-time scrapers, and a surprising amount of real bot traffic, look like on the wire:
`User-Agent: python-requests/2.x`, `Accept: */*`, and nothing a browser would send.

Expected:
  DEFENSE_LEVEL=0     5/5 pages
  DEFENSE_LEVEL>=1    0/5, X-Lab-Signals: ua:red_flag

    python attacks/round1_naive_requests.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from headers_client import Tally, bot, fetch_catalog, finish, requests_defaults  # noqa: E402


def run():
    return fetch_catalog(bot("naive-requests", 1), requests_defaults(), Tally("round1_naive_requests")).result()


if __name__ == "__main__":
    print("=== Round 1: python-requests defaults ===")
    finish(run())
