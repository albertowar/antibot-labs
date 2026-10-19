"""
Chapter 9, Round 3 attack: humanized Camoufox + an account farm (Section 9.7).

The scalper fixes everything Round 2's layers measure:

  - humanize: curved Bezier paths, overshoot on long moves, a random click point inside each target, key
    holds and gaps with human-looking noise (attacks/humanize.py, W2 Ch5's ghost-cursor recipe, copied
    byte for byte; the events are trusted because Camoufox's browser dispatches them)
  - browse like a customer: login page, home page, wander, then the drop page
  - linger on the drop page before pressing Reserve
  - type every field key by key instead of page.fill()

What the browser cannot fix is the business reality of scalping: one pair per account means one ACCOUNT per
pair. The farm registers its accounts in bulk just before the drop (over plain HTTP, since registration is
barely defended), and they all ship to the same reshipper with different unit numbers.

Expected:
    level 0 to 3   reserved
    level 4 and up blocked: session_model p(bot) >= threshold (fresh account, an address shared by the farm)

Setup (once):  python -m camoufox fetch
Run:           python attacks/round3_humanized_farm.py [--sessions 3]
"""

import argparse
import time

from camoufox.sync_api import Camoufox
from curl_cffi import requests as cffi

from humanize import Cursor, human_type

from _common import (BASE_URL, CLAIM, DROP, Cost, bot_ip, browser_ctx, farm_identity, finish, open_drop, refused, report,
                     rng_for, submit)


def register_accounts(rng, n):
    """Bulk-create the farm's accounts right before the drop."""
    accounts = []
    for _ in range(n):
        ident = farm_identity(rng)
        s = cffi.Session(impersonate="firefox147")
        h = {"X-Lab-Client-IP": bot_ip(rng), "X-Lab-Actor": "bot:round3_farm", "X-Lab-JA4": CLAIM["gecko"]}
        r = s.post(BASE_URL + "/api/register", headers=h, json=ident)
        if r.status_code == 201:
            accounts.append(ident)
    return accounts


def aim(page, cursor, selector):
    """A person scrolls to what they want to press. Camoufox draws a random window size, and the Reserve
    button can sit below a short one; the mouse cannot click what is off screen."""
    page.locator(selector).scroll_into_view_if_needed()
    cursor.click(selector)


def wander(page, cursor, rng):
    for _ in range(rng.randint(2, 4)):
        cursor.move_to(rng.uniform(100, 1000), rng.uniform(100, 600))
        time.sleep(rng.uniform(0.1, 0.4))


def run(sessions=3, verbose=False):
    rng = rng_for("round3")
    results = []
    with Cost() as cost:
        accounts = register_accounts(rng, sessions)
        for ident in accounts:
            with Camoufox(headless=True, os=rng.choice(["windows", "macos"])) as browser:
                ctx = browser_ctx(browser, "bot:round3_farm", CLAIM["gecko"])
                page = ctx.new_page()
                cursor = Cursor(page)
                page.goto(BASE_URL + "/login")
                for sel, key in (("#login-form input[name=email]", "email"), ("#login-form input[name=password]", "password")):
                    aim(page, cursor, sel)
                    human_type(page, ident[key])
                with page.expect_navigation(timeout=30000):
                    aim(page, cursor, "#login-form button[type=submit]")
                result = refused(open_drop(page))
                if result is None:
                    wander(page, cursor, rng)
                    time.sleep(rng.uniform(1.0, 2.0))
                    for field, sel in (("name", "#name"), ("email", "#email"), ("size", "#size")):
                        if page.locator(sel).count():
                            aim(page, cursor, sel)
                            human_type(page, ident[field])
                            time.sleep(rng.uniform(0.2, 0.6))
                    result = submit(page, lambda: aim(page, cursor, "#drop-buy"))
                results.append(result)
                if verbose:
                    report(f"round3_farm #{len(results)}", results[-1])
    for _ in range(sessions - len(accounts)):          # accounts the store refused to create are pairs not bought
        results.append({"status": "blocked", "http": 403, "verdict": "block", "signals": ["register_refused"]})
    return results, cost, len(accounts)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=3)
    print("=== Round 3: humanized Camoufox farm ===")
    results, cost, accounts = run(ap.parse_args().sessions, verbose=True)
    finish("round3_farm", results, cost, accounts=accounts)
