"""
W2 Ch1 — Round 0 Attack: Raw HTTP Scraper (Section 1.6, Round 0)

Objective: confirm where Workshop 1 left us. A raw HTTP client asks the API
for the catalogue and tries to add to the cart, with no browser at all.

Expected results:
  - every DEFENSE_LEVEL → 403 from the edge layer (Workshop 1 header rules):
    "[W1-UA] UA red flag: ..." on the default python-httpx User-Agent.
  - Round 1 (round1_header_replay.py) shows what happens when the headers
    are copied from a real browser instead.

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=0 python app.py
Then run:
    python attacks/round0_httpx_scraper.py
"""

import httpx

from _common import BASE_URL, CART_PATH, SCRAPE_PATH, report, require_local, result


def run():
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    require_local()
    with httpx.Client(base_url=BASE_URL, timeout=5) as client:
        r1 = client.get(SCRAPE_PATH)
        if r1.status_code != 200:
            return [result(SCRAPE_PATH, r1.status_code, r1.text),
                    {"path": CART_PATH, "status": None, "reasons": ["never reached the cart"]}]
        r2 = client.post(CART_PATH, json={"product_id": 4})
    return [result(SCRAPE_PATH, r1.status_code, r1.text), result(CART_PATH, r2.status_code, r2.text)]


if __name__ == '__main__':
    report("Round 0: python-httpx defaults", run())
