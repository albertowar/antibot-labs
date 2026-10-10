"""
W2 Ch1 — Round 2 Attack: Turn the Automation Flags Off (Section 1.6, Round 2)

Objective: beat Layer 1. Two launch options remove the obvious tells:

  ignore_default_args=["--enable-automation"]
      Playwright adds this flag by default; it sets navigator.webdriver and
      shows the "controlled by automated software" infobar.
  --disable-blink-features=AutomationControlled
      Forces navigator.webdriver to false even if something else enabled it.

The identity override from Round 1 stays. No exposed functions or init
scripts are used, so no driver globals appear in the page.

Expected results (verified with Playwright 1.63 / Chromium 153):
  - DEFENSE_LEVEL<=1 → 200 (webdriver is false, no globals)
  - DEFENSE_LEVEL>=2 → 403, headless shell contradicts itself:
      "[L2] No browser UI: outer window equals the viewport (1280x720)"
      "[L2] Notification.permission is 'denied' but permissions.query says 'prompt'"
      "[L2] Desktop Chromium with 0 plugins ...", "no window.chrome object",
      "[L2] Software WebGL renderer (... SwiftShader ...)"

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=1 python app.py
Then run:
    python attacks/round2_flags_off.py
"""

from playwright.sync_api import sync_playwright

from _common import cdp_identity_override, report, shop_in_browser

STEALTH_LAUNCH = {
    "args": ["--disable-blink-features=AutomationControlled"],
    "ignore_default_args": ["--enable-automation"],
}


def run():
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    with sync_playwright() as p:
        browser = p.chromium.launch(**STEALTH_LAUNCH)
        context = browser.new_context()
        page = context.new_page()
        cdp_identity_override(context, page, browser.version)
        results = shop_in_browser(page)
        browser.close()
    return results


if __name__ == '__main__':
    report("Round 2: automation flags off", run())
