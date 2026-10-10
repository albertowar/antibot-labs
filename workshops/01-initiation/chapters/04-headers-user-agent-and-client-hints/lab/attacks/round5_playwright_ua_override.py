"""
Chapter 4 — Round 5 Attack: Give Up on Faking, Drive a Real Browser (Section 4.7)

Objective: modelling Chrome's headers by hand is a losing game, so the
attacker launches a real Chromium with Playwright. The default headless UA
says "HeadlessChrome", so they override it with a Windows Chrome UA built
from the real browser version.

Recent Playwright versions are careful: they derive matching Client Hints
from the override (Sec-CH-UA-Platform becomes "Windows"). What the override
does NOT change is the brand list Chromium builds from the real binary.

Expected results (verified with Playwright 1.63 / Chromium 153):
  - --no-override: DEFENSE_LEVEL>=1 → 403, "[L1] UA red flag: Headless Chrome"
  - with override: DEFENSE_LEVEL=2 → 200 (only "[L2] Missing Accept-Language", 15 pts)
                   DEFENSE_LEVEL>=3 → 403, "[L3] Sec-CH-UA brand list contains HeadlessChrome"
                   DEFENSE_LEVEL=4  → also "[L4] Platform-Version '10.0' is not in browser format"

Setup (once):
    playwright install chromium
Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=3 python app.py
Then run:
    python attacks/round5_playwright_ua_override.py [--no-override]
"""

import json
import os
import sys

from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")


def run(override=True, verbose=False):
    """
    Run the attack in a real headless Chromium. Returns one result per request
    (used by tools/checkpoint.py).
    """
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        major = browser.version.split(".")[0]
        options = {}
        if override:
            options["user_agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
            )
        context = browser.new_context(**options)
        page = context.new_page()

        if verbose:
            label = "UA override" if override else "default headless UA"
            print(f"=== Round 5: Playwright Chromium {browser.version} ({label}) ===")

        for path in ["/", "/api/products", "/api/products"]:
            response = page.goto(f"{BASE_URL}{path}")
            reasons = []
            if response.status == 403:
                reasons = json.loads(page.inner_text("body")).get("reasons", [])
            results.append({"path": path, "status": response.status, "reasons": reasons})

        if verbose:
            for result in results:
                print(f"  GET {result['path']:<14} {result['status']}")
                for reason in result["reasons"]:
                    print(f"    - {reason}")

            # What did the server actually see?
            page.goto(f"{BASE_URL}/header-check")
            seen = json.loads(page.inner_text("body"))
            print("\n  Headers the server received:")
            for name, value in seen["headers_received"]:
                if name.lower().startswith("sec-ch") or name == "User-Agent":
                    print(f"    {name}: {value}")
        browser.close()
    return results


if __name__ == '__main__':
    run(override="--no-override" not in sys.argv, verbose=True)
