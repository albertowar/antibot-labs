"""
Chapter 8, Round 2 attack: render the page, fill what is visible.

Objective: stop guessing from the HTML. Load the signup page in a real Chromium, let the CSS apply, and
fill only the inputs Playwright reports as visible. Then wait a little longer than a fast human before
submitting.

`locator.is_visible()` means "has a non-empty box and is not visibility:hidden". A display:none field
fails that test. A field moved off-screen still passes: it has a box, just not one inside the viewport.

    python attacks/round2_playwright_form.py            # needs: python -m playwright install chromium

Expected:   the Round 2 starting state (.hp-offscreen honeypot named "phone"): trapped, because the
            off-screen field counts as visible.
            after the Round 2 fix (.hp, display:none): every signup is created. The fix that protects
            real users is exactly what lets this bot through.
            every level: the 2-second wait beats the timing token.
"""

import json
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import trapkit  # noqa: E402  (labclient runs the localhost guard on import)
from trapkit import BASE_URL, TEXT_TYPES, world_pool  # noqa: E402
from labclient import browser_context  # noqa: E402

ACTOR = "bot:r2_playwright"
WAIT_MS = 2000


def run(attempts=3, verbose=False):
    from playwright.sync_api import sync_playwright
    ip, believed = world_pool("cloud_vm")[3], 0
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for i in range(attempts):
            context = browser_context(browser, ACTOR, ip)       # carries the lab headers, refuses non-local URLs
            page = context.new_page()
            page.goto(f"{BASE_URL}/register")
            user = f"pw{i}-{secrets.token_hex(3)}"
            for field in page.locator("form#register-form input").all():
                kind = field.get_attribute("type") or "text"
                if kind not in TEXT_TYPES:
                    continue
                if not field.is_visible():
                    if verbose and i == 0:
                        print(f"    skipping invisible field {field.get_attribute('name')!r}")
                    continue
                field.fill(trapkit.fill_value({"type": kind, "autocomplete": field.get_attribute("autocomplete") or ""}, user))
            page.wait_for_timeout(WAIT_MS)
            page.click("form#register-form button[type=submit]")
            page.wait_for_load_state()
            ok = page.url.endswith("/account")
            believed += ok
            if verbose:
                print(f"  signup {user:<14} -> {page.url.replace(BASE_URL, '')}")
            context.close()
        browser.close()
    if verbose:
        print(f"\nBot's view: {believed}/{attempts} signups succeeded.")
        print("Server's view: python tools/scoreboard.py")
    return {"attempted": attempts, "succeeded": believed}


if __name__ == "__main__":
    print("=== Round 2: Playwright, visible fields only ===")
    print(json.dumps(run(verbose=True)))
