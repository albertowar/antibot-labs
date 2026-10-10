"""
W2 Ch1 — Round 1 Attack: Fix the Headers over CDP (Section 1.6, Round 1)

Objective: get past the Workshop 1 header rules with a real browser. The
attacker keeps Playwright's default launch but rewrites the browser's
identity through the Chrome DevTools Protocol (Emulation.setUserAgentOverride
with userAgentMetadata). That changes the User-Agent, Accept-Language and
the Sec-CH-UA brands, so the HTTP layer sees a clean "Google Chrome 153".

What it does NOT change: navigator.webdriver is still true, because
Playwright launches Chromium with --enable-automation.

Expected results (verified with Playwright 1.63 / Chromium 153):
  - DEFENSE_LEVEL=0  → 200 on /api/products and /api/cart (edge rules pass)
  - DEFENSE_LEVEL>=1 → 403, "[L1] navigator.webdriver is true ..."

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=0 python app.py
Then run:
    python attacks/round1_playwright_cdp_override.py
"""

from playwright.sync_api import sync_playwright

from _common import cdp_identity_override, report, shop_in_browser


def run():
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context()
        page = context.new_page()
        cdp_identity_override(context, page, browser.version)
        results = shop_in_browser(page)
        browser.close()
    return results


if __name__ == '__main__':
    report("Round 1: Playwright + CDP identity override", run())
