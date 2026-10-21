"""
W3 Ch8's shoppers: real browsers, because the controls only mean something in one.

CSP, SRI, nonces and the runtime monitor are enforced by the browser, so the shoppers who could be
hurt by them have to be browsers too. Each shopper is a persona from the starter's 40, played by
headless Chromium behind the same lab edge (`X-Lab-Client-IP`, `X-Lab-Actor`) and the same guard
that refuses any request that is not to this machine. Two shoppers' worth of the chapter's slice:

    scenario   what each person does
    ---------  ------------------------------------------------------------------------------------
    ch5_shop   open a product, add it to the cart, pay as a guest (card, expiry, CVC), then sign in
               to their own account. "bought" only if the order is confirmed AND the sign-in lands
               on /account; anything else counts as hurt, because the store is the one that broke.

Two things are measured besides finishing:
  - first-party violations: console errors from the browser refusing something the store itself
    serves (a script without a nonce, a blocked stylesheet). Must be 0: a policy that breaks your own
    pages is a regression. The vendor file refused by SRI and the skimmer's own refused calls are
    counted apart (that is the control working).
  - report noise: the `consumer_vpn` and `old_chrome` shoppers run a privacy add-on that injects a
    tracker pixel and an inline script into every page. Under the strict policy the browser refuses
    both and files CSP reports. Nobody is hurt, but the report stream fills with traffic that is not
    an attack, which is the real operational cost of CSP.

The shoppers go one browser at a time (the checkpoint runs them next to the attacks).
"""

import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import population  # noqa: E402
import labclient  # noqa: E402
from labclient import BASE_URL  # noqa: E402
from labnet import target  # noqa: E402

COLLECTOR = target("COLLECTOR_URL", "http://127.0.0.1:5001")

_SERIAL = threading.Lock()
NOISY = {"consumer_vpn", "old_chrome"}                  # the shoppers with a privacy add-on
VIOLATION_MARKERS = ("Refused to", "Content Security Policy", "Failed to find a valid digest")

ADDON = """
document.addEventListener('DOMContentLoaded', function () {
  var i = new Image(); i.src = 'https://tracker-blocker.example.test/pixel.png';
  var s = document.createElement('script'); s.textContent = 'window.__addon = 1';
  document.documentElement.appendChild(s);
});
"""


def _watch(page, tally):
    def on_console(msg):
        text = msg.text
        if msg.type == "error" and any(m in text for m in VIOLATION_MARKERS):
            if "tracker-blocker.example.test" in text:
                tally["addon"] += 1
            elif COLLECTOR in text:                 # the skimmer, trying to phone home from the shopper's page
                tally["skimmer"] += 1
            elif "analytics-helper" in text:
                tally["vendor"] += 1
            else:
                tally["first_party"] += 1
    page.on("console", on_console)


def scenario_shop(p, client, rng):
    from demo_site.seed import password_for, username
    from playwright.sync_api import sync_playwright
    tally = {"first_party": 0, "vendor": 0, "addon": 0, "skimmer": 0}
    stage = "start"
    try:
        with _SERIAL, sync_playwright() as pw:
            browser = pw.chromium.launch()
            ctx = labclient.browser_context(browser, p.actor, ip=p.ip)
            if p.persona in NOISY:
                ctx.add_init_script(ADDON)
            page = ctx.new_page()
            _watch(page, tally)
            stage = "cart"
            page.goto(f"{BASE_URL}/product/p001", wait_until="load")
            with page.expect_response(lambda r: r.request.method == "POST" and "/cart/add" in r.url, timeout=10000):
                page.click("#add-to-cart")
            page.wait_for_load_state("load")
            stage = "checkout"
            page.goto(f"{BASE_URL}/checkout", wait_until="load")
            email = p.actor.replace(":", ".") + "@example.test"
            page.fill("form#checkout input[name=email]", email)
            for name, value in (("name", "Pat Shopper"), ("address", "1 Trail Way"), ("city", "Boulder"), ("postcode", "80301"),
                                ("card", "4242424242424242"), ("exp", "12/29"), ("cvc", "123")):
                page.fill(f"form#checkout input[name={name}]", value)
            page.click("form#checkout button[type=submit]")
            page.wait_for_selector('[data-testid="order-confirmed"]', timeout=10000)
            stage = "login"
            page.goto(f"{BASE_URL}/login", wait_until="load")
            page.fill("form#login-form input[name=email]", username(p.account))
            page.fill("form#login-form input[name=password]", password_for(p.account))
            page.click("form#login-form button[type=submit]")
            page.wait_for_url(f"{BASE_URL}/account**", timeout=10000)
            ctx.close()
            browser.close()
    except Exception as exc:
        print(f"[ch5_shop] {p.actor} did not finish: stuck at {stage}: {type(exc).__name__}: {str(exc).splitlines()[0][:160]}")
        p.result.update(stage=stage, error_type=type(exc).__name__, **{f"csp_{k}": v for k, v in tally.items()})
        return population._stop(p, client, "blocked", None)
    p.result.update(stage="done", **{f"csp_{k}": v for k, v in tally.items()})
    return population._stop(p, client, "bought", None)


population.SCENARIOS["ch5_shop"] = scenario_shop
