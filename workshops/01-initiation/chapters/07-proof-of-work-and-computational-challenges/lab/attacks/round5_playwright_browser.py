"""
Chapter 7 — Round 5 Attack: let the browser pay

Objective: stop re-implementing the solver. Drive a real Chromium with
Playwright, let the store's own JavaScript solve every challenge in its
Web Workers, and read the catalog through the page's gatedFetch().

The bot now pays exactly what a human pays, per pass, and PoW has nothing
left to say: it *prices* requests, it does not *identify* clients.
Telling this browser apart from a human is Workshop 2 (automation
detection in W2 Ch1, behavior in W2 Ch3).

Expected results (any level):
  - 60/60 pages, solve times in line with your /pow-bench numbers.

Needs: pip install playwright && playwright install chromium

Run:
    python attacks/round5_playwright_browser.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from _common import BASE_URL, Tally, report  # noqa: E402

BROWSER_IP = "203.0.113.77"
PAGES_WANTED = 60  # three passes' worth at level 3+

FETCH_PAGE = "async n => (await gatedFetch(`/api/products?page=${n}`)).status"


def run():
    """Run the attack; return its scoreboard row (used by tools/checkpoint.py)."""
    from playwright.sync_api import sync_playwright

    tally = Tally("round5_playwright_browser", wanted=PAGES_WANTED)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(extra_http_headers={"X-Sim-Client-IP": BROWSER_IP})
        page.goto(BASE_URL)
        page.wait_for_function("typeof gatedFetch === 'function'")
        for n in range(1, PAGES_WANTED + 1):
            status = page.evaluate(FETCH_PAGE, n)
            if status != 200:
                tally.note(f"page {n}: {status}")
                break
            tally.pages_ok += 1
        solves = page.evaluate("window.powStats.solves")
        workers = page.evaluate("POW_WORKERS")
        browser.close()
    for s in solves:
        tally.solves += 1
        tally.bits.append(s["bits"])
        tally.hashes += s["tried"]
        # every worker is busy for the whole solve: CPU ≈ wall time × workers
        tally.cpu_s += s["ms"] / 1000 * workers
    if solves:
        ms = ", ".join(f"{s['ms']:.0f} ms ({s['bits']} bits)" for s in solves)
        tally.note(f"browser solves with {workers} workers: {ms}")
    return tally.result()


if __name__ == "__main__":
    print("=== Round 5: Playwright, the page solves its own challenges ===")
    report(run())
