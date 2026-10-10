"""
Chapter 4 — Round 1 Attack: Naive Scraper (Section 4.7)

Objective: scrape the product catalogue with python-requests defaults. This
is what most first-time scrapers (and a surprising amount of real bot
traffic) look like on the wire.

Expected results:
  - DEFENSE_LEVEL=0 → 200, products scraped
  - DEFENSE_LEVEL=1 → 403, "[L1] UA red flag: Raw HTTP library (Python requests)"

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=0 python app.py
Then run:
    python attacks/round1_naive_requests.py
"""

import os

import requests

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")
TARGET_URL = f"{BASE_URL}/api/products"


def to_result(path, r):
    data = r.json()
    return {"path": path, "status": r.status_code, "data": data,
            "reasons": data.get("reasons", []) if r.status_code == 403 else []}


def report(result):
    print(f"  Status: {result['status']}")
    if result["status"] == 200:
        print(f"  Scraped: {[p['name'] for p in result['data']['products']]}")
    else:
        print(f"  Blocked (score {result['data'].get('score')}):")
        for reason in result["reasons"]:
            print(f"    - {reason}")
    print()


def run():
    """Run the attack; return one result per scraping request (used by tools/checkpoint.py)."""
    return [to_result("/api/products", requests.get(TARGET_URL, timeout=5))]


if __name__ == '__main__':
    print("=== Round 1: python-requests defaults ===")
    for result in run():
        report(result)
