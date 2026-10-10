"""
Chapter 2 — Rounds 0-1 Attack: a plain HTTP scraper (Section 2.7)

Objective: scrape the whole catalog with requests. No JavaScript, no
browser. This is the bulk of real-world scraping traffic, and it's what a
JavaScript challenge exists to filter out.

Expected results:
  - DEFENSE_LEVEL=0   → 300/300 pages
  - DEFENSE_LEVEL>=1  → 0/300, "no valid js_ok cookie" (or "no clearance cookie" at 2+)

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=0 python app.py
Then run:
    python attacks/round1_requests_scraper.py
"""

import requests

from common import BASE_URL, CHROME_UA, report, require_local, result, scrape


def run():
    require_local()
    session = requests.Session()
    session.headers["User-Agent"] = CHROME_UA
    ok, reason, seconds = scrape(session)
    return result("round1_requests_scraper", ok, reason, seconds)


if __name__ == '__main__':
    print(f"Round 1 attack: plain requests scraper -> {BASE_URL}")
    report(run())
