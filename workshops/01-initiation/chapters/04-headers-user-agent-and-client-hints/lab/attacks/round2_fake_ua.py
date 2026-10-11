"""
Chapter 4 — Round 2 Attack: Borrow a Chrome User-Agent (Section 4.7)

Objective: the server blocks python-requests by its User-Agent, so the
attacker pastes a Chrome UA string and changes nothing else.

Expected results:
  - DEFENSE_LEVEL=1 → 200, the UA now parses as Chrome 153 on Windows
  - DEFENSE_LEVEL=2 → 403, missing Accept-Language, no Sec-Fetch-*, Accept */*

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=1 python app.py
Then run:
    python attacks/round2_fake_ua.py
"""

import os
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

TARGET_URL = f"{BASE_URL}/api/products"

# Update the major version to current stable before teaching
CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")


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
    r = requests.get(TARGET_URL, headers={"User-Agent": CHROME_UA}, timeout=5)
    return [to_result("/api/products", r)]


if __name__ == '__main__':
    print("=== Round 2: Chrome User-Agent, everything else default ===")
    for result in run():
        report(result)
