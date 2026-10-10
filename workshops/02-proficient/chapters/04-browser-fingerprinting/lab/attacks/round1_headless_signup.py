"""
Chapter 4 — Round 1 Attack: Default Headless Sign-up Farm (Section 4.7)

Objective: claim the €10 welcome credit 20 times. Each sign-up uses a fresh
browser context (new cookies, new session) and a different simulated IP,
so the IP rate limits from W1 Ch2/Ch3 see 20 unrelated visitors.

The browser is Playwright's default headless Chromium: it runs the
collector honestly, so the store sees the real render stack of a server
with no GPU.

Expected results:
  - DEFENSE_LEVEL=0: 20/20 accounts created
  - DEFENSE_LEVEL>=1: 0/20, "[L1] SwiftShader WebGL renderer ..."

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=0 python app.py
Then:
    python attacks/round1_headless_signup.py [--signups 20]
"""

import argparse

from playwright.sync_api import sync_playwright

from _lab import bot_email, lab_ip, report, require_local, sign_up


def run(signups=20, verbose=False):
    require_local()
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for i in range(signups):
            context = browser.new_context(extra_http_headers={"X-Lab-Client-IP": lab_ip(i)})
            results.append(sign_up(context.new_page(), bot_email(1, i)))
            context.close()
        browser.close()
    if verbose:
        report("Round 1: default headless Chromium", results)
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--signups", type=int, default=20)
    run(parser.parse_args().signups, verbose=True)
