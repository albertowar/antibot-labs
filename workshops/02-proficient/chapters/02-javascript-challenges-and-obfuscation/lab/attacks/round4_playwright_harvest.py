"""
Chapter 2 — Round 4 Attack: solve in a real browser, scrape with requests (Section 2.7)

Objective: Round 4's challenge needs a layout engine and native DOM code, so
jsdom fails. Fine: use a real browser. But only for the challenge.
Headless Chromium solves it once, then we copy its cookies (sid + clr) and
its exact User-Agent (the clearance is bound to it) into requests and
scrape at HTTP speed.

This is "clearance harvesting", and it's how most JS-challenge bypass tooling
works in practice. The browser costs ~1-2 s and ~150 MB of RAM per solve; every
request after that costs the same as Round 0.

Note what we did NOT need: no stealth plugin, no patched browser. The
challenge only asks "is this a real engine?", and it is. Spotting the
automation is W2 Ch1's job.

Expected results:
  - DEFENSE_LEVEL<=4 → 300/300 pages, 1 browser solve
  - DEFENSE_LEVEL=5  → ~29/300, then "clearance budget spent (30/30)"

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=4 python app.py
Then run:
    python attacks/round4_playwright_harvest.py
"""

import time

import requests
from playwright.sync_api import sync_playwright

from common import BASE_URL, report, require_local, result, scrape


def harvest(page):
    """Load the store in the browser until the challenge is solved. Returns (cookies, ua)."""
    page.goto(f"{BASE_URL}/")
    page.wait_for_selector("#products", timeout=15000)
    cookies = {c["name"]: c["value"] for c in page.context.cookies()}
    return cookies, page.evaluate("navigator.userAgent")


def to_session(cookies, ua):
    session = requests.Session()
    session.headers["User-Agent"] = ua
    for name, value in cookies.items():
        session.cookies.set(name, value)
    return session


def run():
    require_local()
    t0 = time.perf_counter()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        cookies, ua = harvest(page)
        browser.close()
    solve_seconds = time.perf_counter() - t0
    pages, reason, seconds = scrape(to_session(cookies, ua))
    return result("round4_playwright_harvest", pages, reason, seconds + solve_seconds, 1, solve_seconds)


if __name__ == '__main__':
    print(f"Round 4 attack: headless Chromium solves, requests scrapes -> {BASE_URL}")
    report(run())
