"""
W1 Ch9 — Wave 4: a real browser for every hoodie (beats Round 4).

The attacker accepts the price Round 4 set. No handoff, no reuse: each
hoodie gets its own headless Chromium context (consistent headers via
browser_kit) on its own sticky residential IP, which browses like a
person (home page, click through, type an email, pick a size, wait a
moment) and lets the page's JavaScript solve the proof of work.

To an HTTP-level defense, this IS a shopper. Every W1 signal is genuine:
clean IP, real Chromium headers in real order, a session that saw the
form, a JS cookie, a solved proof of work, one purchase per session.

What it costs the attacker, and what Workshop 2 adds:
  - a browser per unit and a sticky residential IP per unit: real money
    at scale, which is the whole point of W1's layers
  - automation leaves traces below HTTP: navigator.webdriver and CDP
    artefacts (W2 Ch1), a JS challenge that checks the environment
    (W2 Ch2), mouse and keyboard behaviour (W2 Ch3), fingerprint
    consistency (W2 Ch4), and the TLS/HTTP2 handshake (W2 Ch5)

Expected (tools/checkpoint.py):
  Round 4 / Drop Day  still buys a share of the drop

Needs a browser: playwright install chromium

    python attacks/wave4_full_browser.py
"""

import asyncio
import json
import os
import random
import sys
import time
from collections import Counter

from playwright.async_api import async_playwright

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from browser_kit import new_page  # noqa: E402
from labclient import BASE_URL, world_pool  # noqa: E402

BROWSERS = 3         # sessions in flight at once
MAX_SESSIONS = 30
DEADLINE = 40        # seconds


async def one_session(browser, ip, i, rng, totals):
    context, page = await new_page(browser, ip, "bot:wave4")
    try:
        r = await page.goto(BASE_URL + "/")
        totals["statuses"][r.status] += 1
        await page.wait_for_timeout(rng.uniform(300, 900))
        await page.click("a[href='/drop']")
        await page.wait_for_load_state()
        if not await page.query_selector("#checkout"):
            totals["outcomes"]["no_form"] += 1
            return
        await page.fill("input[name=email]", f"fb{i}@scalp.example")
        await page.select_option("select[name=size]", "M")
        await page.wait_for_timeout(rng.uniform(1100, 1600))
        async with page.expect_navigation(timeout=30000) as nav:
            await page.click("#buy")
        response = await nav.value
        totals["statuses"][response.status] += 1
        text = await page.content()
        if response.status == 200 and "Order" in text:
            totals["believed"] += 1
            totals["outcomes"]["bought"] += 1
        else:
            totals["outcomes"][response.status] += 1
            if response.status == 410:
                totals["sold_out"] = True
    except Exception as exc:
        totals["outcomes"][type(exc).__name__] += 1
    finally:
        await context.close()


async def main(seed):
    pool = world_pool("residential_proxy")
    rng = random.Random(seed)
    totals = {"believed": 0, "statuses": Counter(), "outcomes": Counter(), "sold_out": False, "sessions": 0}
    started = time.perf_counter()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        sem = asyncio.Semaphore(BROWSERS)

        async def guarded(i):
            async with sem:
                if totals["sold_out"] or time.perf_counter() - started > DEADLINE:
                    return
                totals["sessions"] += 1
                await one_session(browser, rng.choice(pool), i, rng, totals)

        await asyncio.gather(*(guarded(i) for i in range(MAX_SESSIONS)))
        await browser.close()
    return totals


def run(seed=4):
    totals = asyncio.run(main(seed))
    return {"wave": "wave4", "believed": totals["believed"], "requests": sum(totals["statuses"].values()),
            "statuses": {str(k): v for k, v in totals["statuses"].items()}, "pow_seconds": None,
            "browser_sessions": totals["sessions"], "outcomes": {str(k): v for k, v in totals["outcomes"].items()}}


if __name__ == '__main__':
    result = run()
    if "--json" in sys.argv:
        print(json.dumps(result))
    else:
        print(f"=== Wave 4: one real browser per hoodie ===\n  believes it bought {result['believed']} hoodies "
              f"in {result['browser_sessions']} browser sessions · outcomes {result['outcomes']}")
