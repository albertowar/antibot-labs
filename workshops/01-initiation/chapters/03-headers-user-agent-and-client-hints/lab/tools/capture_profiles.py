"""
Chapter 3: capture real-browser header profiles.

Opens real, headed browsers with Playwright, visits the store and saves what /lab/headers/check saw
into tools/profiles/, for tools/replay_profiles.py to replay.

Run the store at DEFENSE_LEVEL=4 first, so it sends Accept-CH and the Chromium profile includes its
high-entropy hints:
    DEFENSE_LEVEL=4 python demo_site/app.py
Then (needs a display; headless browsers do NOT count as real users):
    python tools/capture_profiles.py

The session and device cookies (sid, did) are dropped from the saved headers: they are this run's
identifiers and mean nothing to the next store. `ch_offered` stays; it is what makes level 4 check the hints.

Caveat: Playwright's Firefox and WebKit are patched builds, close to but not
identical to stock Firefox and Safari. Prefer captures from your own browsers
(save /lab/headers/check as JSON), and record where each profile came from.
"""

import json
import os
import platform
import sys
from datetime import date

from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from labclient import BASE_URL  # noqa: E402  (the localhost guard)

PROFILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")

BROWSERS = [
    ("chrome", "chromium", {"channel": "chrome"}),   # installed Google Chrome
    ("firefox", "firefox", {}),
    ("webkit", "webkit", {}),
]


def _own_cookies_only(cookie_header):
    keep = [c.strip() for c in cookie_header.split(";") if c.strip().startswith("ch_offered=")]
    return "; ".join(keep)


def capture(p, name, engine, options):
    browser = getattr(p, engine).launch(headless=False, **options)
    page = browser.new_page()
    page.goto(f"{BASE_URL}/")
    page.wait_for_timeout(1000)       # let the page's fetch() and Accept-CH settle
    page.goto(f"{BASE_URL}/lab/headers/check")
    data = json.loads(page.inner_text("body"))
    if "headers_received" not in data:
        browser.close()
        raise RuntimeError(f"{BASE_URL} is not the Chapter 3 store: {data}")
    data["headers_received"] = [[n, _own_cookies_only(v) if n.lower() == "cookie" else v] for n, v in data["headers_received"]]
    data["headers_received"] = [[n, v] for n, v in data["headers_received"] if v]
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
