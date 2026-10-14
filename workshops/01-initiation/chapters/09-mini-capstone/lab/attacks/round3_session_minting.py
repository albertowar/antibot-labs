"""
Round 3 attack (beats traps and the session guard): mint sessions in a browser, spend them with scripts.

The attacker read W1 Ch5 and W1 Ch8. Form fillers die on the honeypot and the timing token, so let a
real browser do the parts that need a browser, once, and let cheap scripts do the rest:

  1. MINT.  A headless Chromium (consistent headers) loads the home page, clicks through to the drop
            and waits a human moment on a residential address. The page script sets js_ok, the server
            records the landing and the visit, and the browser sees which fields are really visible
            (the honeypot is not). The attacker keeps the cookies and the form values, and closes it.
  2. SPEND. Plain requests workers post ONLY the visible fields (the honeypot stays empty) with the
            same Chrome headers, through the proxy network's cheap rotating mode: a new residential
            address for every request. Each minted session tries to buy up to 5 hoodies.

One browser launch, many purchases: that is the economics this wave depends on.

Expected (tools/checkpoint.py):
  Round 3  takes most of the drop: every session signal is genuine
  Round 4  stopped: the proof of work is bound to the IP + User-Agent that solved it and the challenge
           to the IP that was served it, so a worker on a rotating address cannot pay (the session
           moved networks, too: asn_changed); and one hoodie per session caps whatever does get through

Needs a browser: pip install -r requirements-browser.txt && python -m playwright install chromium

    python attacks/round3_session_minting.py
    python attacks/round3_session_minting.py --pinned     # README bonus 4: the workers keep the minter's own address
"""

import asyncio
import sys
import random
import threading

import _drop as d
from labclient import BASE_URL, LabClient, world_pool

SESSIONS = 6         # browser sessions to mint
MINTERS = 6          # browser contexts minting in parallel
PER_SESSION = 5      # hoodies each minted session should buy
WORKERS = 6
PINNED = "--pinned" in sys.argv     # a sticky proxy session instead of the cheap rotating mode

FIELDS = """() => [...document.querySelectorAll("form.buy input")].filter(i => i.name).map(i => ({
    name: i.name, type: i.type, value: i.value, checked: i.checked,
    visible: i.type === "hidden" || !!(i.offsetWidth || i.offsetHeight || i.getClientRects().length)}))"""


async def mint(pool, rng, tally):
    from playwright.async_api import async_playwright
    minted = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        sem = asyncio.Semaphore(MINTERS)

        async def one(ip):
            async with sem:
                context, page = await d.async_page(browser, "bot:r3_minter", ip)
                try:
                    await page.goto(BASE_URL + "/")
                    await page.click(f"a.drop-card[data-sku='{d.SKU}']")
                    await page.wait_for_selector("form.buy", timeout=30000)     # a proof of work solves itself here
                    await page.wait_for_timeout(1100)                           # let the form "age"
                    seen = await page.evaluate(FIELDS)
                    form = {f["name"]: f["value"] for f in seen if f["visible"] and f["type"] in ("hidden",)}
                    form.update({f["name"]: f["value"] for f in seen if f["type"] == "radio" and f["checked"]})
                    minted.append({"cookies": {c["name"]: c["value"] for c in await context.cookies()}, "form": form, "ip": ip})
                except Exception as exc:
                    tally.extra.setdefault("mint_errors", []).append(type(exc).__name__)   # blocked or broken
                finally:
                    await context.close()

        await asyncio.gather(*(one(rng.choice(pool)) for _ in range(SESSIONS)))
        await browser.close()
    return minted


def spend(minted, pool, tally):
    lock, sold_out = threading.Lock(), threading.Event()
    jobs = list(enumerate(minted))

    def worker():
        while not sold_out.is_set():
            with lock:
                if not jobs:
                    return
                i, session = jobs.pop(0)
            # rotating mode: a new residential address for every request; --pinned: the address that minted the session
            shop = LabClient("bot:r3_minter", ip=session["ip"]) if PINNED else LabClient("bot:r3_minter", pool=pool)
            for name in ("sid", "did", "js_ok"):
                if name in session["cookies"]:
                    shop.set_cookie(name, session["cookies"][name])
            bought = tried = refused = 0
            while bought < PER_SESSION and tried < PER_SESSION * 3 and not sold_out.is_set():
                tried += 1
                hdrs = d.chrome("post", BASE_URL + d.PATH)
                r = shop.post(d.PATH, {**session["form"], "email": f"mint{i}.{tried}@scalp.example"}, hdrs)
                if d.bought(r):
                    bought, refused = bought + 1, 0
                elif r.status_code == 410:
                    sold_out.set()
                elif r.status_code == 403 and d.solve_interstitial(shop, r, tally, hdrs):
                    continue                                       # paid: try the post again
                else:
                    refused += 1
                    if refused >= 2:
                        break                                      # blocked, or the pass will not hold
            with lock:
                tally.believed += bought
                tally.attempted += tried
                tally.count(shop)

    threads = [threading.Thread(target=worker) for _ in range(WORKERS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def run(seed=3):
    tally, pool = d.Tally("round3_session_minting"), world_pool("residential_proxy_net")
    minted = asyncio.run(mint(pool, random.Random(seed), tally))
    tally.extra["browser_sessions"] = len(minted)
    spend(minted, pool, tally)
    tally.requests += 2 * SESSIONS
    return tally


if __name__ == "__main__":
    d.finish("Round 3: minted sessions, rotating workers", run())
