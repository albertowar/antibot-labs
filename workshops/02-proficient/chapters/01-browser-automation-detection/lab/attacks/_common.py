"""
Shared helpers for the W2 Ch1 attack scripts.

Rules of engagement, enforced in code: every attack targets the local demo
store only. require_local() refuses any other host, so a typo in DEMO_URL
cannot point these scripts at somebody else's site.
"""

import json
import os
import sys
from urllib.parse import urlparse

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# The paths every attack reports on (tools/checkpoint.py reads these)
SCRAPE_PATH = "/api/products"
CART_PATH = "/api/cart"


def require_local(url=BASE_URL):
    """Exit unless `url` points at this machine."""
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        sys.exit(f"Refusing to run against {url}: lab attacks only target localhost.")
    return url


def result(path, status, body=None):
    reasons = []
    if status == 403 and body:
        try:
            reasons = json.loads(body).get("reasons", [])
        except ValueError:
            pass
    return {"path": path, "status": status, "reasons": reasons}


def shop_in_browser(page, base_url=BASE_URL, click=None):
    """
    Visit the store like a shopper: load the page (the sensor runs), wait for
    the product list, then add the first product to the cart.

    `click(page, button)` performs the click (default: Playwright's
    button.click()). Returns one result per API call the page made.
    """
    require_local(base_url)
    seen = {}

    def on_response(response):
        path = urlparse(response.url).path
        if path in (SCRAPE_PATH, CART_PATH):
            try:
                body = response.text()
            except Exception:
                body = None
            seen[path] = result(path, response.status, body)

    page.on("response", on_response)
    response = page.goto(f"{base_url}/")
    if response.status != 200:
        # The edge layer blocked the page itself: the sensor never ran
        page.remove_listener("response", on_response)
        blocked = result(SCRAPE_PATH, response.status, response.text())
        blocked["reasons"] = [f"(page GET / blocked) {r}" for r in blocked["reasons"]]
        return [blocked, {"path": CART_PATH, "status": None, "reasons": ["never reached the cart"]}]
    page.wait_for_selector('#status:not([data-state="loading"])', timeout=15000)
    button = page.query_selector(".add-to-cart")
    if button is not None:
        (click or (lambda p, b: b.click()))(page, button)
        page.wait_for_selector('#cart-status:not([data-state="idle"])', timeout=10000)
    page.remove_listener("response", on_response)
    results = [seen.get(SCRAPE_PATH, {"path": SCRAPE_PATH, "status": None, "reasons": ["page made no request"]})]
    if SCRAPE_PATH in seen and seen[SCRAPE_PATH]["status"] == 200:
        results.append(seen.get(CART_PATH, {"path": CART_PATH, "status": None, "reasons": ["no cart request"]}))
    else:
        results.append({"path": CART_PATH, "status": None, "reasons": ["never reached the cart"]})
    return results


def report(title, results):
    print(f"=== {title} ===")
    for r in results:
        status = r["status"] if r["status"] is not None else "-"
        mark = "✅ got through" if r["status"] == 200 else ("⛔ blocked" if r["status"] == 403 else "…")
        print(f"  {r['path']:<14} {status!s:<4} {mark}")
        for reason in r["reasons"]:
            print(f"      - {reason}")
    print()


def chrome_ua(major, platform="Linux"):
    """A current, frozen-format Chrome User-Agent for `platform`."""
    os_token = {
        "Linux": "X11; Linux x86_64",
        "Windows": "Windows NT 10.0; Win64; x64",
        "macOS": "Macintosh; Intel Mac OS X 10_15_7",
    }[platform]
    return (f"Mozilla/5.0 ({os_token}) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.0.0 Safari/537.36")


def cdp_identity_override(context, page, full_version, platform="Linux"):
    """
    Rewrite the browser's identity over the Chrome DevTools Protocol:
    User-Agent, Accept-Language AND the userAgentData / Sec-CH-UA brands.
    This changes HTTP headers and navigator.* together, which is what makes
    the Workshop 1 header rules see a clean "Google Chrome".

    Limitation the defenders will exploit: the override applies to this
    page's target only. Dedicated Workers are separate targets and keep the
    real identity unless the attacker also attaches to them.
    """
    major = full_version.split(".")[0]
    brands = [{"brand": "Google Chrome", "version": major},
              {"brand": "Chromium", "version": major},
              {"brand": "Not_A Brand", "version": "8"}]
    full_list = [{"brand": "Google Chrome", "version": full_version},
                 {"brand": "Chromium", "version": full_version},
                 {"brand": "Not_A Brand", "version": "8.0.0.0"}]
    session = context.new_cdp_session(page)
    session.send("Emulation.setUserAgentOverride", {
        "userAgent": chrome_ua(major, platform),
        "acceptLanguage": "en-US,en",       # navigator.languages; Chrome adds the q-values
        "platform": {"Linux": "Linux x86_64", "Windows": "Win32", "macOS": "MacIntel"}[platform],
        "userAgentMetadata": {
            "brands": brands, "fullVersionList": full_list,
            "platform": platform, "platformVersion": {"Linux": "6.8.0", "Windows": "19.0.0",
                                                      "macOS": "15.6.0"}[platform],
            "architecture": "x86", "model": "", "mobile": False, "bitness": "64",
        },
    })
    return session
