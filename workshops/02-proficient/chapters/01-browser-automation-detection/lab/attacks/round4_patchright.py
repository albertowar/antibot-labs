"""
W2 Ch1 — Round 4 Attack: Patch the Driver, Not the Page (Section 1.6, Round 4)

Objective: beat Layer 3 by not lying in JavaScript at all. Every value the
page reads must come from the browser itself, so the attacker changes the
browser's configuration instead of patching its API:

  patchright       A drop-in Playwright fork that patches the DRIVER: no
                   --enable-automation, no Runtime.enable, page.evaluate()
                   runs in an isolated world, expose_function() leaves no
                   __playwright__binding__ global behind.
  new headless     channel="chromium" runs Chrome's "new" headless (the real
                   browser code, not headless shell): plugins, window.chrome
                   and the permission APIs behave like desktop Chrome.
  CDP emulation    The UA override is applied by Playwright to every target
                   (pages AND workers), and the window/screen geometry is set
                   with Emulation.setDeviceMetricsOverride and
                   Browser.setWindowBounds. Native getters, native values.

It also uses expose_function() to report progress, a common pattern in real
bots. Run the same script with plain Playwright (--vanilla) and Layer 1
catches the binding it leaves in the page.

What remains: a software WebGL renderer (weak signal) and the way
page.click() moves the mouse.

Expected results (verified with patchright 1.63 / Chromium 153):
  - DEFENSE_LEVEL<=3 → 200 on /api/products and /api/cart
      (only "[L2] Software WebGL renderer", 10 points: clean)
  - DEFENSE_LEVEL=4  → /api/products 200 (scraping still works!)
                       /api/cart 403: "[L4] Pointer teleported ...",
                       "[L4] Click landed on the exact centre of the button"
  - --vanilla, DEFENSE_LEVEL>=1 → 403, "[L1] Automation global found
      (Playwright exposed binding: __playwright__binding__)"

Setup (once):
    python -m patchright install chromium
Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=3 python app.py
Then run:
    python attacks/round4_patchright.py [--vanilla]
"""

import sys

from _common import chrome_ua, report, shop_in_browser

VIEWPORT = {"width": 1366, "height": 768}


def run(vanilla=False, click=None):
    """Run the attack; return one result per API call (used by tools/checkpoint.py)."""
    if vanilla:
        from playwright.sync_api import sync_playwright
    else:
        from patchright.sync_api import sync_playwright
    progress = []
    with sync_playwright() as p:
        # --lang sets the browser's real language list, so Workers agree with the page.
        # (Playwright's `locale` option emulates it for the page only: Layer 3 sees that.)
        launch = {"channel": "chromium", "args": ["--lang=en-US"]}
        if vanilla:
            launch["args"].append("--disable-blink-features=AutomationControlled")
            launch["ignore_default_args"] = ["--enable-automation"]
        browser = p.chromium.launch(**launch)
        major = browser.version.split(".")[0]
        context = browser.new_context(user_agent=chrome_ua(major), viewport=VIEWPORT)
        context.expose_function("reportProgress", lambda step: progress.append(step))
        page = context.new_page()
        cdp = context.new_cdp_session(page)
        cdp.send("Emulation.setDeviceMetricsOverride", {
            **VIEWPORT, "deviceScaleFactor": 1, "mobile": False,
            "screenWidth": 1920, "screenHeight": 1080})
        window = cdp.send("Browser.getWindowForTarget")["windowId"]
        cdp.send("Browser.setWindowBounds", {"windowId": window, "bounds": {
            "width": VIEWPORT["width"] + 16, "height": VIEWPORT["height"] + 88}})
        results = shop_in_browser(page, click=click)
        browser.close()
    return results


if __name__ == '__main__':
    vanilla = "--vanilla" in sys.argv
    report(f"Round 4: {'plain Playwright' if vanilla else 'patchright'}, new headless, CDP emulation",
           run(vanilla=vanilla))
