"""
Chapter 4 — Capture Real-Browser Header Profiles (Section 4.7)

Opens real, headed browsers with Playwright, visits the demo store and saves
what /header-check saw into tools/profiles/, for legit_traffic.py to replay.

Run the demo site at DEFENSE_LEVEL=4 first, so the server sends Accept-CH
and the Chromium profile includes its high-entropy hints:
    cd demo_site && DEFENSE_LEVEL=4 python app.py
Then (needs a display; headless browsers do NOT count as real users):
    python tools/capture_profiles.py

Caveat: Playwright's Firefox and WebKit are patched builds, close to but not
identical to stock Firefox and Safari. Prefer captures from your own browsers
(save /header-check as JSON), and record where each profile came from.
"""

import json
import os
import sys
import platform
from datetime import date

from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

PROFILES_DIR = os.path.join(os.path.dirname(__file__), "profiles")

BROWSERS = [
    ("chrome", "chromium", {"channel": "chrome"}),   # installed Google Chrome
    ("firefox", "firefox", {}),
    ("webkit", "webkit", {}),
]


def capture(p, name, engine, options):
    browser = getattr(p, engine).launch(headless=False, **options)
    page = browser.new_page()
    page.goto(f"{BASE_URL}/")
    page.wait_for_timeout(1000)       # let the page's fetch() and Accept-CH settle
    page.goto(f"{BASE_URL}/header-check")
    data = json.loads(page.inner_text("body"))
    if "headers_received" not in data:
        browser.close()
        raise RuntimeError(f"{BASE_URL} is not the Chapter 4 demo site: {data}")
    version = browser.version
    browser.close()

    data["name"] = f"{name}-{version.split('.')[0]}-{platform.system().lower()}"
    data["source"] = f"Playwright {engine} ({name}) {version}, headed, {platform.system()}"
    data["captured"] = date.today().isoformat()
    path = os.path.join(PROFILES_DIR, f"{data['name']}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  saved {path}  (verdict when captured: {data['verdict']})")


if __name__ == '__main__':
    os.makedirs(PROFILES_DIR, exist_ok=True)
    with sync_playwright() as p:
        for name, engine, options in BROWSERS:
            try:
                capture(p, name, engine, options)
            except Exception as e:
                why = str(e)
                if "missing dependencies" in why:
                    why = f"missing system libraries (run: sudo playwright install-deps {engine})"
                elif "is not found at" in why or "Executable doesn't exist" in why:
                    why = f"browser not installed (run: playwright install {engine})"
                print(f"  skipped {name}: {why.splitlines()[0]}")
