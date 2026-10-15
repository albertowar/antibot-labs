"""
Shared helpers for the round attacks.

Every attack plays the same scene. The skimmer is already in place (the vendor include was swapped,
or a first-party build was poisoned); what the attacker needs is VICTIMS: real people filling in the
checkout and the login form in a real browser. So the script drives Chromium (Playwright) through
the store's pages as two victims, one at the card field and one at the password field, and after
each asks the local collector whether the data arrived.

What changes between rounds is the exfil technique (`variant`, set on the store before the run) and
the control the store has switched on (DEFENSE_LEVEL). The attack never touches the store's
defenses; it only picks its technique.

Ethics guardrail: tools/labclient.py runs the labnet guard, and its browser context aborts every
request that is not to this machine. The collector's address goes through labnet too.

Every attack script ends by printing one JSON line: {"attempted": victims, "succeeded": victims
whose data reached the collector, ...}.
"""

import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import labclient  # noqa: E402  (runs the labnet guard on import)
from labclient import BASE_URL, admin, world_pool  # noqa: E402
from labnet import target  # noqa: E402

COLLECTOR = target("COLLECTOR_URL", "http://127.0.0.1:5001")

VICTIM_CARD = "4242424242424242"       # the synthetic test number; never type a real card into a lab


def collector(path, method="GET"):
    req = urllib.request.Request(COLLECTOR + path, method=method)
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read() or b"{}")


def reset_collector():
    collector("/reset", "POST")


def captured():
    try:
        return collector("/captured")
    except OSError as exc:
        raise SystemExit(f"The collector is not reachable on {COLLECTOR}: {exc}. Start it: python collector/collector.py")


def set_scenario(**kw):
    """Tell the store which exfil technique the compromise uses (and whether the CSP is Report-Only)."""
    return admin("POST", "/lab/supply/scenario", json=kw)


def _is_cart_add(response):
    return response.request.method == "POST" and "/cart/add" in response.url


def add_to_cart(page, base):
    """A shopper's first steps: open a product and add it, so /checkout renders the payment form."""
    page.goto(f"{base}/product/p001", wait_until="load")
    with page.expect_response(_is_cart_add, timeout=10000):   # store.js adds over fetch; without it the form posts
        page.click("#add-to-cart")                             # /checkout is an empty-cart redirect until this lands
    page.wait_for_load_state("load")


def fill_checkout(page, email):
    page.fill("form#checkout input[name=email]", email)
    for name, value in (("name", "Pat Victim"), ("address", "1 Trail Way"), ("city", "Boulder"),
                        ("postcode", "80301"), ("card", VICTIM_CARD), ("exp", "12/29"), ("cvc", "123")):
        page.fill(f"form#checkout input[name={name}]", value)


def victim_checkout(browser, base, ip):
    """One victim pays. Returns the page's outcome so the script can say what the victim saw."""
    ctx = labclient.browser_context(browser, "human:victim:checkout", ip=ip)
    page = ctx.new_page()
    try:
        add_to_cart(page, base)
        page.goto(f"{base}/checkout", wait_until="load")
        fill_checkout(page, "victim.checkout@example.test")
        page.click("form#checkout button[type=submit]")
        page.wait_for_selector('[data-testid="order-confirmed"]', timeout=8000)
        page.wait_for_timeout(500)                       # let beacons and pixels land
        return "paid"
    except Exception as exc:                             # the victim's own experience is not the point
        return f"error: {type(exc).__name__}"
    finally:
        ctx.close()


def victim_login(browser, base, ip):
    from demo_site.seed import password_for, username
    ctx = labclient.browser_context(browser, "human:victim:login", ip=ip)
    page = ctx.new_page()
    try:
        page.goto(f"{base}/login", wait_until="load")
        page.fill("form#login-form input[name=email]", username(7))
        page.fill("form#login-form input[name=password]", password_for(7))
        page.click("form#login-form button[type=submit]")
        page.wait_for_url(f"{base}/account**", timeout=8000)
        page.wait_for_timeout(500)
        return "signed in"
    except Exception as exc:
        return f"error: {type(exc).__name__}"
    finally:
        ctx.close()


def run(label, variant, report_only=False, base=BASE_URL):
    """Set the technique, run two victims, return {attempted, succeeded, ...}. Prints what happened."""
    from playwright.sync_api import sync_playwright
    set_scenario(variant=variant, vendor="compromised", report_only=report_only)   # the compromise is in place
    admin("POST", "/lab/supply/reset")
    status = admin("GET", "/lab/supply/status")
    print(f"=== {label} ===")
    print(f"  store: level {status['level']}  csp={status['controls']['csp']}/{status['controls']['policy']}  "
          f"sri={status['controls']['sri']}  monitor={status['controls']['monitor']}  variant={variant}")
    ips = world_pool("home_broadband")
    results, errors = [], 0
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for name, flow, ip in (("checkout (card)", victim_checkout, ips[0]), ("login (password)", victim_login, ips[1])):
            reset_collector()
            seen = flow(browser, base, ip)
            if seen.startswith("error"):                  # a slow first paint is not a defense: try the victim once more
                reset_collector()
                seen = flow(browser, base, ip)
            errors += seen.startswith("error")
            cap = captured()
            got = cap["sensitive"] > 0
            results.append(got)
            via = f" via {cap['items'][0]['via']}" if got else ""
            print(f"  victim at the {name}: {seen}; "
                  f"{'EXFIL SUCCEEDED' if got else 'nothing sensitive reached the collector'}{via}")
        browser.close()
    after = admin("GET", "/lab/supply/status")
    out = {"attempted": len(results), "succeeded": sum(results), "variant": variant, "level": after["level"],
           "victim_errors": errors, "csp_reports": after["csp_reports"],
           "monitor_reports": after["violations"]}
    print(json.dumps(out))
    return out
