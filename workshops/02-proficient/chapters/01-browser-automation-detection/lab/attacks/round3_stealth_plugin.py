"""
W2 Ch1 — Round 3 Attack: Patch the JavaScript Environment (Section 1.6, Round 3)

Objective: beat Layer 2 by making every value it reads look right. This is
what stealth plugins do: playwright-stealth (2.x, the Python port of
puppeteer-extra-plugin-stealth's evasions) injects init scripts that
replace navigator.plugins, window.chrome, the Permissions API, WebGL vendor
strings and more with JavaScript fakes. Its own README calls it a proof of
concept, and that is exactly why it is useful here: it shows the technique.

Stealth does not fix the window geometry, so the attacker adds one more
init script of their own that fakes outerWidth/outerHeight (browser UI
height) and Notification.permission.

The identity override from Round 1 and the flags from Round 2 stay. The
stealth plugin's own User-Agent and Client Hints patches are switched off
because the CDP override already handles them consistently.

Expected results (verified with Playwright 1.63 / Chromium 153, playwright-stealth 2.0.3):
  - DEFENSE_LEVEL<=2 → 200 (every Layer 2 value now looks plausible)
  - DEFENSE_LEVEL>=3 → 403:
      "[L3] Native code replaced by script: Navigator.plugins, ..."
      "[L3] Another JavaScript realm disagrees with the page: Worker ua, ..."

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=2 python app.py
Then run:
    python attacks/round3_stealth_plugin.py
"""

from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth

from _common import cdp_identity_override, report, shop_in_browser
from round2_flags_off import STEALTH_LAUNCH

# The attacker's own patch for what stealth does not cover
GEOMETRY_PATCH = """
(() => {
  const fake = (obj, prop, value) =>
    Object.defineProperty(obj, prop, { get: () => value(), configurable: true });
  fake(window, 'outerWidth', () => window.innerWidth + 16);
  fake(window, 'outerHeight', () => window.innerHeight + 88);
  if (window.Notification) fake(Notification, 'permission', () => 'default');
})();
"""


def run():
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    stealth = Stealth(
        navigator_user_agent=False,       # the CDP override handles identity
        navigator_user_agent_data=False,
        sec_ch_ua=False,
        navigator_platform=False,
        navigator_platform_override=None,
    )
    with sync_playwright() as p:
        browser = p.chromium.launch(**STEALTH_LAUNCH)
        context = browser.new_context()
        stealth.apply_stealth_sync(context)
        context.add_init_script(GEOMETRY_PATCH)
        page = context.new_page()
        cdp_identity_override(context, page, browser.version)
        results = shop_in_browser(page)
        browser.close()
    return results


if __name__ == '__main__':
    report("Round 3: playwright-stealth + geometry patch", run())
