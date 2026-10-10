"""
Shared helpers for the Chapter 3 attack scripts.

Rules of engagement, enforced in code: every script targets the local demo
store only. require_local() refuses anything that isn't localhost, and no
script supports proxies.
"""

import os
import random
import time
from urllib.parse import urlparse

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Synthetic identities only.
NAMES = ["Ada Quill", "Bo Reyes", "Cy Novak", "Dee Okafor", "Eli Marsh", "Fay Lindqvist"]


def require_local(url=BASE_URL):
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        raise SystemExit(f"Refusing to attack {host!r}: lab scripts only target localhost.")
    return url


def identity(rng=random):
    name = rng.choice(NAMES)
    user = name.lower().replace(" ", ".")
    return {"name": name, "email": f"{user}{rng.randint(1, 999)}@example.test",
            "size": str(rng.randint(38, 46))}


def open_drop(playwright, label, headless=True):
    """Launch Chromium, open /drop with the lab label header. Returns (browser, page)."""
    require_local()
    browser = playwright.chromium.launch(headless=headless)
    context = browser.new_context(viewport={"width": 1280, "height": 720},
                                  extra_http_headers={"X-Lab-Client": label})
    page = context.new_page()
    page.goto(f"{BASE_URL}/drop")
    return browser, page


def box(page, selector):
    return page.locator(selector).bounding_box()


def wait_result(page, timeout_ms=10000):
    """Wait for the page to show the server's verdict and return it."""
    page.wait_for_selector("#result[data-status]", timeout=timeout_ms)
    return page.evaluate("window.lastReserve")


def report(name, result):
    mark = {"reserved": "🟢", "challenge": "🟡", "blocked": "🔴"}.get(result["status"], "?")
    print(f"  {mark} {name:<28} {result['status']:<9} score={result['score']}")
    for reason in result.get("reasons", []):
        print(f"       - {reason}")


def sleep_ms(ms):
    time.sleep(max(0, ms) / 1000)
