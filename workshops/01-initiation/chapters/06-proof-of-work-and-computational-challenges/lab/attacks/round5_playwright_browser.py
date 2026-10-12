"""
Chapter 6, Round 5 attack: let the browser pay.

Objective: stop re-implementing the solver. Drive a real Chromium with Playwright, let the
store's own JavaScript solve every challenge in its Web Workers, and read the catalog through
the page's own gatedFetch().

The bot now pays exactly what a human pays, per pass, and PoW has nothing left to say: it
*prices* requests, it does not *identify* clients. Telling this browser apart from a human is
Workshop 2 (automation artefacts in W2 Ch1, behavior in W2 Ch3).

Expected (any level): 60/60 products, solve times in line with your /lab/pow/bench numbers.

Needs: pip install -r requirements-browser.txt && python -m playwright install chromium

    python attacks/round5_playwright_browser.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from labclient import BASE_URL, browser_context, world_pool  # noqa: E402
from pow_client import SKUS, Tally, finish  # noqa: E402

WANTED = 60  # three passes' worth at level 3+

FETCH = "async sku => (await gatedFetch(`/api/products/${sku}`)).status"


def run():
    from playwright.sync_api import sync_playwright

    tally = Tally("round5_playwright_browser", wanted=WANTED)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser_context(browser, "bot:pow-browser", ip=world_pool("cloud_vm")[30]).new_page()
        page.goto(BASE_URL + "/")
        page.wait_for_function("typeof gatedFetch === 'function'")
        for sku in SKUS[:WANTED]:
            status = page.evaluate(FETCH, sku)
            if status != 200:
                tally.note(f"{sku}: {status}")
                break
            tally.pages_ok += 1
        solves = page.evaluate("window.powStats.solves")
        workers = page.evaluate("POW_WORKERS")
        browser.close()
    for s in solves:
        tally.solves += 1
        tally.bits.append(s["bits"])
        tally.hashes += s["tried"]
        tally.cpu_s += s["ms"] / 1000 * workers      # every worker is busy for the whole solve
    if solves:
        tally.note(f"browser solves with {workers} workers: " + ", ".join(f"{s['ms']:.0f} ms ({s['bits']} bits)" for s in solves))
    return tally.result()


if __name__ == "__main__":
    print("=== Round 5: Playwright, the page solves its own challenges ===")
    finish(run())
