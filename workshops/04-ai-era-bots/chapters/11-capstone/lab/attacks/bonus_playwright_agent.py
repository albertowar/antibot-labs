"""
Bonus (optional) — a real browser agent against checkout.

Everything else in this lab models agents at the HTTP layer so a round runs in
seconds with no browser. This bonus drives a real Chromium through the store the
way an agentic browser would: load the product, add to cart, fill checkout,
click. It exists so you can confirm the HTTP-level story holds against a real
DOM-driven agent, and watch the behaviour layer (W2 Ch5/Ch9, shadow here) light
up next to the agent signals.

Needs Chromium:  pip install playwright==1.63.0 && python -m playwright install chromium
Loopback only; one aged synthetic account.

    python attacks/bonus_playwright_agent.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from _common import owner_accounts, target  # noqa: E402


def run(base=None, headless=None):
    base = target() if base is None else base
    if headless is None:
        headless = os.environ.get("HEADLESS", "1") not in ("0", "false", "no")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright is not installed. This bonus is optional:\n"
              "  pip install playwright==1.63.0 && python -m playwright install chromium")
        return None
    acct = owner_accounts(1)[0]
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()
        page.goto(f"{base}/login")
        page.fill('input[name="email"]', acct["email"])
        page.fill('input[name="password"]', acct["password"])
        page.click("#login-submit")
        page.wait_for_timeout(500)
        page.goto(f"{base}/product/lab-runner-9")
        page.click("#add-to-cart")
        page.wait_for_timeout(500)
        page.goto(f"{base}/checkout")
        page.click("#place-order")
        page.wait_for_timeout(800)
        body = page.inner_text("#result") if page.query_selector("#result") else page.content()[:400]
        browser.close()
    print(f"[bonus playwright agent] checkout result: {body[:200]}")
    return {"result": body}


if __name__ == "__main__":
    run()
