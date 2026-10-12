"""
W2 Ch1 — Round 0 Attack: Raw HTTP Scraper (Section 1.6, Round 0)

Objective: confirm where Workshop 1 left us. A raw HTTP client asks the API
for the catalogue and tries to add to the cart, with no browser at all.

Expected results:
  - DEFENSE_LEVEL=0 (the bare store) → 200 on both
  - DEFENSE_LEVEL>=1 → 403 from W1's header rules (Round 0's level):
    `ua:red_flag` (python-httpx) and the headers no browser omits.

Run the store first (python demo_site/app.py), then:
    python attacks/round0_httpx_scraper.py
"""

import httpx

from _common import BASE_URL, CART_PATH, SCRAPE_PATH, bot_ip, finish, report, result


def run():
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    lab = {"X-Lab-Client-IP": bot_ip(), "X-Lab-Actor": "bot:round0_httpx_scraper"}   # the lab's simulated edge
    with httpx.Client(base_url=BASE_URL, timeout=10, headers=lab) as client:
        r1 = client.get(SCRAPE_PATH)
        if r1.status_code != 200:
            return [result(SCRAPE_PATH, r1.status_code, r1.headers.get("x-lab-signals")),
                    {"path": CART_PATH, "status": None, "signals": ["never reached the cart"]}]
        sku = r1.json()["items"][0]["sku"]
        r2 = client.post(CART_PATH, json={"sku": sku, "qty": 1})
    return [result(SCRAPE_PATH, r1.status_code, r1.headers.get("x-lab-signals")),
            result(CART_PATH, r2.status_code, r2.headers.get("x-lab-signals"))]


if __name__ == '__main__':
    out = run()
    report("Round 0: python-httpx defaults", out)
    finish("round0_httpx_scraper", out)
