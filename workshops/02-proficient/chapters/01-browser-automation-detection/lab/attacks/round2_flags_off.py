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
  - Rounds 0-1 (levels 1-2) → 200 (webdriver is false, no globals)
  - Round 2+ (level 3+)     → 403, consistency: headless shell contradicts itself:
      "No browser UI: outer window equals the viewport (1280x720)"
      "Notification.permission is 'denied' but permissions.query says 'prompt'"
      "Desktop Chromium with 0 plugins ...", "no window.chrome object",
      "Software WebGL renderer (... SwiftShader ...)"

Run the store first (python demo_site/app.py), or let tools/checkpoint.py set the level; then:
    python attacks/round2_flags_off.py
"""

from playwright.sync_api import sync_playwright

from _common import cdp_identity_override, finish, new_context, report, shop_in_browser

STEALTH_LAUNCH = {
    "args": ["--disable-blink-features=AutomationControlled"],
    "ignore_default_args": ["--enable-automation"],
}


def run():
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    with sync_playwright() as p:
        browser = p.chromium.launch(**STEALTH_LAUNCH)
        context = new_context(browser, "round2_flags_off")
        page = context.new_page()
        cdp_identity_override(context, page, browser.version)
        results = shop_in_browser(page)
        browser.close()
    return results


if __name__ == '__main__':
    out = run()
    report("Round 2: automation flags off", out)
    finish("round2_flags_off", out)
