"""
Shared helpers for the W2 Ch1 attack scripts.

Rules of engagement, enforced in code: every attack reaches the store through tools/labclient.py,
which asks labnet.py at the lab root for DEMO_URL and refuses anything that is not this machine.
Browsers get the same guard: labclient.browser_context() aborts every non-local request. The
bots' "residential" source addresses are rented from data/world.json, never real.

Every bot does the same shopping trip as a real visitor: load the store's home page (the sensor
runs), let the Quick add panel load /api/products, then click Add to cart (POST /api/cart/add).
It reports one result per API call and ends by printing one JSON line for tools/checkpoint.py:
{"attempted": 2, "succeeded": <API calls that got a 200>, "products": status, "cart": status}.
The store's X-Lab-Signals header says which checks fired: teaching only, never in production.
"""

import json
import os
import random
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
from labclient import BASE_URL, browser_context, world_pool  # noqa: E402

# The paths every attack reports on (tools/checkpoint.py reads these)
SCRAPE_PATH = "/api/products"
CART_PATH = "/api/cart/add"


def bot_ip(rng=random):
    """A rented residential exit: the attacker in this chapter has already paid for clean IPs (W1 Ch3)."""
    return rng.choice(world_pool("residential_proxy_net"))


def new_context(browser, actor, **kw):
    """A browser context that carries the lab headers (rented IP, bot label) and stays on this machine."""
    return browser_context(browser, f"bot:{actor}", ip=bot_ip(), **kw)


def result(path, status, signals=""):
    return {"path": path, "status": status, "signals": [s for s in (signals or "").split(",") if s]}


def shop_in_browser(page, base_url=BASE_URL, click=None):
    """
    Visit the store like a shopper: load the home page (the sensor runs), wait for the Quick add
    panel, then add the first product to the cart.

    `click(page, button)` performs the click (default: Playwright's button.click()). Returns one
    result per API call the page made.
    """
    seen = {}

    def on_response(response):
        path = urlparse(response.url).path
        if path in (SCRAPE_PATH, CART_PATH):
            seen[path] = result(path, response.status, response.headers.get("x-lab-signals"))

    page.on("response", on_response)
    response = page.goto(f"{base_url}/")
    if response.status != 200:
        # The header rules blocked the page itself: the sensor never ran
        page.remove_listener("response", on_response)
        return [result(SCRAPE_PATH, response.status, response.headers.get("x-lab-signals")),
                {"path": CART_PATH, "status": None, "signals": ["never reached the cart"]}]
    page.wait_for_selector('#status:not([data-state="loading"])', timeout=15000)
    button = page.query_selector(".add-to-cart")
    if button is not None:
        (click or (lambda p, b: b.click()))(page, button)
        page.wait_for_selector('#cart-status:not([data-state="idle"])', timeout=10000)
    page.remove_listener("response", on_response)
    results = [seen.get(SCRAPE_PATH, {"path": SCRAPE_PATH, "status": None, "signals": ["page made no request"]})]
    if SCRAPE_PATH in seen and seen[SCRAPE_PATH]["status"] == 200:
        results.append(seen.get(CART_PATH, {"path": CART_PATH, "status": None, "signals": ["no cart request"]}))
    else:
        results.append({"path": CART_PATH, "status": None, "signals": ["never reached the cart"]})
    return results


def report(title, results):
    print(f"=== {title} ===")
    for r in results:
        status = r["status"] if r["status"] is not None else "-"
        mark = "✅ got through" if r["status"] == 200 else ("⛔ blocked" if r["status"] == 403 else "…")
        print(f"  {r['path']:<14} {status!s:<4} {mark}  {' '.join(r['signals'])}")
    print()


def finish(name, results):
    """The last line every attack prints: one JSON object for tools/checkpoint.py."""
    by = {r["path"]: r["status"] for r in results}
    out = {"attack": name, "attempted": 2, "succeeded": sum(r["status"] == 200 for r in results),
           "products": by.get(SCRAPE_PATH), "cart": by.get(CART_PATH),
           "signals": sorted({s for r in results for s in r["signals"] if ":" in s})}
    print(json.dumps(out))
    return out


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
