"""
Chapter 2 — Round 4 Attack: solve in a real browser, scrape with requests (Section 2.7)

Objective: Round 4's challenge needs a layout engine and native DOM code, so
jsdom fails. Fine: use a real browser. But only for the challenge.
Headless Chromium solves it once, then we copy its session cookie (the store
keeps the pass server-side, in that session) and its exact User-Agent (the
pass is bound to it) into requests and scrape at HTTP speed.

This is "clearance harvesting", and it's how most JS-challenge bypass tooling
works in practice. The browser costs ~1-2 s and ~150 MB of RAM per solve; every
request after that costs the same as Round 0.

Note what we did NOT need: no stealth plugin, no patched browser. The
challenge only asks "is this a real engine?", and it is. Spotting the
automation is Chapter 1's job.

Expected results:
  - level 4   → 125/125 records, 1 browser solve
  - level 5   → ~30/125, then challenged again: the clearance budget is spent

Run the store first (python demo_site/app.py), or let tools/checkpoint.py set the level; then:
    python attacks/round4_playwright_harvest.py
"""

import time

from playwright.sync_api import sync_playwright

from _common import BASE_URL, bot_ip, browser_context, finish, lab_session, report, result, scrape

ACTOR = "round4_playwright_harvest"


def harvest(page):
    """Load the catalogue in the browser until the challenge is solved. Returns (cookies, ua)."""
    page.goto(f"{BASE_URL}/products")
    page.wait_for_selector(".product-card", timeout=20000)      # the interstitial reloads into the catalogue
    cookies = {c["name"]: c["value"] for c in page.context.cookies()}
    return cookies, page.evaluate("navigator.userAgent")


def to_session(cookies, ua, ip, actor=ACTOR):
    session = lab_session(actor, ua=ua, ip=ip)
    for name, value in cookies.items():
        session.cookies.set(name, value)
    return session


def run():
    ip = bot_ip()
    t0 = time.perf_counter()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser_context(browser, f"bot:{ACTOR}", ip=ip).new_page()
        cookies, ua = harvest(page)
        browser.close()
    solve_seconds = time.perf_counter() - t0
    got, reason, seconds, _ = scrape(to_session(cookies, ua, ip))
    return result(ACTOR, got, reason, seconds + solve_seconds, 1, solve_seconds)


if __name__ == '__main__':
    print(f"Round 4 attack: headless Chromium solves, requests scrapes -> {BASE_URL}")
    r = run()
    report(r)
    finish(r)
