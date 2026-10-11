"""
Chapter 4 — Round 3 Attack: Replay a Full Browser Header Set (Section 4.7)

Objective: the attacker copies a complete set of browser headers (the kind
found in countless scraping tutorials, or "Copy as cURL" from an older
browser) so every presence and Sec-Fetch check passes. The Referer and
Sec-Fetch-Site are even adjusted to the target.

What the attacker did not copy: Client Hints. And python-requests still
puts its own default headers first, so the order is not Chrome's.

Expected results:
  - DEFENSE_LEVEL=2 → 200
  - DEFENSE_LEVEL=3 → 403, "[L3] UA claims Chromium 153 but Sec-CH-UA is absent"
                           "[L3] Header order unlike Chromium ..."

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=2 python app.py
Then run:
    python attacks/round3_devtools_copy.py
"""

import os
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

TARGET_URL = f"{BASE_URL}/api/products"

CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")

COPIED_HEADERS = {
    "User-Agent": CHROME_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": f"{BASE_URL}/",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


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
    r = requests.get(TARGET_URL, headers=COPIED_HEADERS, timeout=5)
    return [to_result("/api/products", r)]


if __name__ == '__main__':
    print("=== Round 3: full browser header set, copied ===")
    for result in run():
        report(result)
