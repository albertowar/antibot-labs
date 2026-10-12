"""
W2 Ch1 — Round 0 Attack: Out-of-the-Box Playwright (Section 1.6, Round 0)

Objective: the same shopping trip in a real browser, with Playwright's
defaults. Since Chrome 132 removed the old headless mode from the main
binary, Playwright's default headless launch uses the separate
`chromium-headless-shell` build, which announces itself everywhere:
"HeadlessChrome" in the User-Agent and in the Sec-CH-UA brands.

Expected results (verified with Playwright 1.63 / Chromium 153):
  - DEFENSE_LEVEL=0 (the bare store) → 200
  - DEFENSE_LEVEL>=1 → 403 from W1's header rules (Round 0's level): HeadlessChrome in the
    User-Agent and in the Sec-CH-UA brands. The home page itself is blocked.

Setup (once):
    python -m playwright install chromium
Run the store first (python demo_site/app.py), then:
    python attacks/round0_playwright_default.py
"""

from playwright.sync_api import sync_playwright

from _common import finish, new_context, report, shop_in_browser


def run():
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = new_context(browser, "round0_playwright_default").new_page()
        results = shop_in_browser(page)
        browser.close()
    return results


if __name__ == '__main__':
    out = run()
    report("Round 0: Playwright defaults (headless shell)", out)
    finish("round0_playwright_default", out)
