"""
Chapter 9, Round 0 attack: the naive fleet (Section 9.7).

Three cheap bots, the kind that is still most of the bot traffic on the internet. Run them once so you have
seen every Round 0 layer fire (level 1):

    --tool requests      python-requests: a library UA, a library TLS stack, no JavaScript
                         -> ua_inspector, header_inspector, ja4_denylist (W2 Ch1, Ch5) at the request,
                            sensor_gate at the buy
    --tool curl_cffi     a perfect Chrome ClientHello and header set, but not a browser: no JavaScript
                         -> nothing at the request (its TLS and headers ARE Chrome's), sensor_gate at the buy
    --tool playwright    stock headless Chromium, nothing hidden
                         -> HeadlessChrome in the UA and Client Hints, navigator.webdriver (W2 Ch1)

Expected: 0 pairs bought at level 1 and above; at level 0 (no defenses) every one buys.

Run (store running):
    python attacks/round0_naive.py --tool requests
"""

import argparse
import sys

from _common import (BASE_URL, CLAIM, DROP, FIELDS, SELECTOR, SIZES, Cost, LabClient, bot_ip, browser_ctx, farm_identity,
                     finish, from_response, open_drop, refused, report, rng_for, submit)


def library(rng):
    """python-requests with its defaults: the lazy bot (W1 Ch4)."""
    c = LabClient("bot:round0_requests", ip=bot_ip(rng), ja4=CLAIM["python"], rng=rng)
    hdrs = [("User-Agent", "python-requests/2.34.2"), ("Accept-Encoding", "gzip, deflate"), ("Accept", "*/*"),
            ("Connection", "keep-alive")]
    c.get(DROP, hdrs)
    return from_response(c.post("/api/buy", json={"sku": "lab-runner-9", "size": rng.choice(SIZES), "email": farm_identity(rng)["email"]},
                                headers=hdrs + [("Content-Type", "application/json")]))


def impersonator(rng):
    """curl_cffi impersonating Chrome 150: the browser's ClientHello and headers, none of its JavaScript."""
    from curl_cffi import requests as cffi
    ip = bot_ip(rng)
    h = {"X-Lab-Client-IP": ip, "X-Lab-Actor": "bot:round0_curl_cffi", "X-Lab-JA4": CLAIM["chromium"]}
    s = cffi.Session(impersonate="chrome150")
    s.get(BASE_URL + DROP, headers=h)
    return from_response(s.post(BASE_URL + "/api/buy", headers=h,
                                json={"sku": "lab-runner-9", "size": rng.choice(SIZES), "email": farm_identity(rng)["email"]}))


def stock_playwright(rng):
    from playwright.sync_api import sync_playwright
    who = farm_identity(rng)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser_ctx(browser, "bot:round0_playwright", CLAIM["chromium"], viewport={"width": 1280, "height": 720})
        page = ctx.new_page()
        result = refused(open_drop(page))
        if result is None:
            for field in FIELDS:
                page.fill(SELECTOR[field], who[field])
            result = submit(page, lambda: page.click(SELECTOR["reserve"]))
        browser.close()
    return result


TOOLS = {"requests": library, "curl_cffi": impersonator, "playwright": stock_playwright}


def run(tool, verbose=False):
    rng = rng_for(f"round0-{tool}")
    with Cost() as cost:
        try:
            result = TOOLS[tool](rng)
        except Exception as exc:                                  # a crashed bot is a lab bug, say so loudly
            print(f"round0 {tool} crashed: {exc!r}", file=sys.stderr)
            raise
    if verbose:
        report(f"round0_{tool}", result)
    return [result], cost


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", choices=sorted(TOOLS), default="requests")
    args = ap.parse_args()
    print(f"=== Round 0: {args.tool} ===")
    results, cost = run(args.tool, verbose=True)
    finish(f"round0_{args.tool}", results, cost)
