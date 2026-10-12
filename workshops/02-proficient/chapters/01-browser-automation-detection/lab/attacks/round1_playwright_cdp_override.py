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
  - Round 0 (level 1)    → 200 on /api/products and /api/cart/add (W1's header rules pass)
  - Round 1+ (level 2+)  → 403, automation_artifacts: navigator.webdriver is true
  (Round N runs at level N+1: defenses/ladder.py.)

Run the store first (python demo_site/app.py), or let tools/checkpoint.py set the level; then:
    python attacks/round1_playwright_cdp_override.py
"""

from playwright.sync_api import sync_playwright

from _common import cdp_identity_override, finish, new_context, report, shop_in_browser


def run():
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = new_context(browser, "round1_playwright_cdp_override")
        page = context.new_page()
        cdp_identity_override(context, page, browser.version)
        results = shop_in_browser(page)
        browser.close()
    return results


if __name__ == '__main__':
    out = run()
    report("Round 1: Playwright + CDP identity override", out)
    finish("round1_playwright_cdp_override", out)
