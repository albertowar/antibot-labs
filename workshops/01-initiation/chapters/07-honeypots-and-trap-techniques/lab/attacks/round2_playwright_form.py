"""
Chapter 7 — Round 2 Attack: Render the Page, Fill What's Visible (Section 7.5)

Objective: stop guessing from the HTML. Load the signup page in a real
Chromium, let the CSS apply, and fill only the inputs Playwright reports as
visible. Then wait a little longer than a fast human before submitting.

`locator.is_visible()` means "has a non-empty box and isn't visibility:hidden".
A display:none field fails that test. A field moved off-screen still passes:
it has a box, just not one inside the viewport.

Expected results:
  - Round 2 starting state (.hp-offscreen honeypot named "phone"): trapped,
    because the off-screen field counts as visible
  - after the Round 2 fix (.hp, display:none): every signup is created.
    The fix that protects real users is exactly what lets this bot through.
  - every level: the 2-second wait beats the timing token

Setup (once):
    playwright install chromium
Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=2 python app.py
Then run:
    python attacks/round2_playwright_form.py
"""

from playwright.sync_api import sync_playwright

from _lab import BASE_URL, TEXT_TYPES, lab_headers, require_local, tag

ACTOR, IP = "round2_playwright_form", "203.0.113.12"
WAIT_MS = 2000


def value_for(kind, user):
    if kind == "email":
        return f"{user}@example.com"
    if kind == "password":
        return f"Pw-{user}-2026"
    return user


def run(attempts=3, verbose=False):
    require_local()
    ok = 0
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for i in range(attempts):
            context = browser.new_context(extra_http_headers=lab_headers(ACTOR, IP))
            page = context.new_page()
            page.goto(f"{BASE_URL}/register")
            user = f"pw{i}-{tag()}"
            for field in page.locator("form#signup input").all():
                kind = field.get_attribute("type") or "text"
                if kind not in TEXT_TYPES:
                    continue
                if not field.is_visible():
                    if verbose and i == 0:
                        print(f"    skipping invisible field {field.get_attribute('name')!r}")
                    continue
                field.fill(value_for(kind, user))
            page.wait_for_timeout(WAIT_MS)
            page.click("form#signup button[type=submit]")
            result = page.locator("#result").get_attribute("data-outcome")
            ok += result == "created"
            if verbose:
                print(f"  signup {user:<14} data-outcome={result}")
            context.close()
        browser.close()
    if verbose:
        print(f"\nBot's view: {ok}/{attempts} signups succeeded.")
        print("Server's view: python tools/scoreboard.py")
    return {"actor": ACTOR, "attempts": attempts, "reported_ok": ok}


if __name__ == "__main__":
    print("=== Round 2: Playwright, visible fields only ===")
    run(verbose=True)
