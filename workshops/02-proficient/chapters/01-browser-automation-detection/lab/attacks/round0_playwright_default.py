"""
W2 Ch1 — Round 0 Attack: Out-of-the-Box Playwright (Section 1.6, Round 0)

Objective: the same shopping trip in a real browser, with Playwright's
defaults. Since Chrome 132 removed the old headless mode from the main
binary, Playwright's default headless launch uses the separate
`chromium-headless-shell` build, which announces itself everywhere:
"HeadlessChrome" in the User-Agent and in the Sec-CH-UA brands.

Expected results (verified with Playwright 1.63 / Chromium 153):
  - every DEFENSE_LEVEL → 403 from the edge layer:
    "[W1-UA] UA red flag: Headless Chrome" and
    "[W1-hints] Sec-CH-UA brand list contains HeadlessChrome"
  - the page loads, but the API calls it makes are blocked

Setup (once):
    python -m playwright install chromium
Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=0 python app.py
Then run:
    python attacks/round0_playwright_default.py
"""

from playwright.sync_api import sync_playwright

from _common import report, shop_in_browser


def run():
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        results = shop_in_browser(page)
        browser.close()
    return results


if __name__ == '__main__':
    report("Round 0: Playwright defaults (headless shell)", run())
