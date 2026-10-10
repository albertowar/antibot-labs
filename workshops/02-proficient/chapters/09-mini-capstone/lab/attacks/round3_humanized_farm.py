"""
Chapter 9 — Round 3 Attack: humanized Camoufox + an account farm (Section 9.7, Part 4)

The scalper fixes everything L2 measures:

  - humanize: Camoufox moves the cursor along curved, accelerating
    paths before every click (implemented inside the browser, so the events
    are trusted)
  - browse like a customer: home page first, wander, then the product page
  - linger on the product page (2–4 s) before clicking Buy
  - type the login with per-key delays

What the browser can't fix is the business reality of scalping: one pair
per account means one *account* per pair. The farm registers its accounts in
bulk just before the drop (over plain HTTP, since registration is barely
defended), and they all ship to the same reshipper with different unit numbers.

Expected results:
    DEFENSE_LEVEL 0–2   3/3 pairs bought
    DEFENSE_LEVEL 3+    0/3   [L3] Session model: p(bot) >= threshold (fresh account, shared address)

Setup (once):  python -m camoufox fetch
Run:           python attacks/round3_humanized_farm.py [--sessions 3]
"""

import argparse
import os
import sys
import time

from camoufox.sync_api import Camoufox
from curl_cffi import requests as cffi

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (Cost, browser_buy, browser_login, egress_pool, farm_identity, report,  # noqa: E402
                     rng_for, summary, target, whoami_sid)


def register_accounts(base, rng, pool, n):
    """Bulk-create the farm's accounts right before the drop."""
    accounts = []
    for _ in range(n):
        ident = farm_identity(rng)
        s = cffi.Session(impersonate="firefox147", verify=False)
        r = s.post(f"{base}/api/register", json=ident, headers={"X-Lab-Egress": rng.choice(pool)})
        if r.status_code == 200:
            accounts.append(ident)
    return accounts


def browse_like_a_human(page, rng):
    for _ in range(rng.randint(1, 3)):
        page.mouse.move(rng.uniform(100, 1000), rng.uniform(100, 600))  # humanized by Camoufox
        time.sleep(rng.uniform(0.1, 0.4))


def run(sessions=3, verbose=False):
    base = target()
    rng = rng_for("round3")
    pool = egress_pool()
    results = []
    with Cost() as cost:
        accounts = register_accounts(base, rng, pool, sessions)
        for ident in accounts:
            with Camoufox(headless=True, humanize=0.8, os=rng.choice(["windows", "macos"])) as browser:
                context = browser.new_context(ignore_https_errors=True,
                                              extra_http_headers={"X-Lab-Egress": rng.choice(pool)})
                page = context.new_page()
                outcome, reasons = browser_login(page, base, ident["email"], ident["password"],
                                                 type_delay=rng.randint(35, 70))
                if outcome == "allow":
                    page.goto(f"{base}/")
                    browse_like_a_human(page, rng)
                    page.click("a[href='/drop/lab-runner-9']")

                    def dwell(p):
                        browse_like_a_human(p, rng)
                        time.sleep(rng.uniform(0.8, 1.8))

                    outcome, reasons = browser_buy(page, base, before_click=dwell)
                results.append({"outcome": outcome, "reasons": reasons, "bought": outcome == "allow",
                                "sid": whoami_sid(page, base)})
    s = summary("round3_humanized_farm", results, cost)
    if verbose:
        report(s)
    return s


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=3)
    run(parser.parse_args().sessions, verbose=True)
