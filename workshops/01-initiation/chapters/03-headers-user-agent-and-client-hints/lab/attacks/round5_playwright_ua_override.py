"""
Chapter 3, Round 5 attack: give up faking, drive a real browser.

Objective: modelling Chrome's headers by hand is a losing game, so the attacker launches a real
Chromium with Playwright. The default headless User-Agent says "HeadlessChrome", so they override
it with a Windows Chrome UA built from the real browser version.

Recent Playwright versions are careful: they derive matching Client Hints from the override
(Sec-CH-UA-Platform becomes "Windows"). What the override does NOT change is the brand list
Chromium builds from the real binary, which still names HeadlessChrome.

Expected (Playwright 1.63 / Chromium 153):
  --no-override   DEFENSE_LEVEL>=1  0/5: ua:red_flag (Headless Chrome)
  with override   DEFENSE_LEVEL<=2  5/5: nothing but at most a missing Accept-Language
                  DEFENSE_LEVEL>=3  0/5: client_hints:headless_brand

Needs: pip install -r requirements-browser.txt && python -m playwright install chromium

    python attacks/round5_playwright_ua_override.py [--no-override]
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from headers_client import BASE_URL, CATALOG_PAGES, Tally, bot, finish  # noqa: E402
from labclient import browser_context, world_pool  # noqa: E402

FETCH = "async url => { const r = await fetch(url); return [r.status, r.headers.get('X-Lab-Signals') || '', r.headers.get('X-Lab-Score') || '0']; }"


def run(override=True):
    from playwright.sync_api import sync_playwright

    tally = Tally("round5_playwright_ua_override" if override else "round5_playwright_headless")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        options = {}
        if override:
            major = browser.version.split(".")[0]
            options["user_agent"] = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                     f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36")
        page = browser_context(browser, "bot:headers-playwright", ip=world_pool("cloud_vm")[5], **options).new_page()
        landing = page.goto(f"{BASE_URL}/")           # the navigation: the store offers Accept-CH here at level 4
        tally.note(f"navigation: {landing.status}")
        for n in range(1, CATALOG_PAGES + 1):
            status, signals, score = page.evaluate(FETCH, f"/api/products?page={n}")
            tally.page(status, signals, score, products=24 if status == 200 else 0)
        # What did the store actually see? (The lab page is ungated, so this works at any level.)
        page.goto(f"{BASE_URL}/lab/headers/check")
        seen = json.loads(page.inner_text("body"))
        tally.note("hints seen: " + "; ".join(f"{n}: {v}" for n, v in seen["headers_received"]
                                              if n.lower().startswith("sec-ch") or n == "User-Agent"))
        browser.close()
    return tally.result()


if __name__ == "__main__":
    override = "--no-override" not in sys.argv
    print(f"=== Round 5: Playwright Chromium ({'UA override' if override else 'default headless UA'}) ===")
    finish(run(override))
