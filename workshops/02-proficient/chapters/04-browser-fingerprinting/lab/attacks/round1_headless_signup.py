"""
Chapter 4, Round 1 attack: the default headless sign-up farm (Section 4.7).

Objective: open accounts in bulk. Each sign-up uses a fresh browser context (new cookies, new
session) and a different rented source address, so the IP defenses from W1 Ch2/Ch3 see 20
unrelated visitors.

The browser is Playwright's default headless Chromium: it runs the collector honestly, so the
store sees the real render stack of a server with no GPU.

Expected results:
  - DEFENSE_LEVEL=0:  20/20 accounts created
  - DEFENSE_LEVEL>=1: 0/20, fp:render_stack ("SwiftShader WebGL renderer ...")

Run the store first (python demo_site/app.py), set the level (curl -X POST localhost:5000/lab/level
-H 'Content-Type: application/json' -d '{"level": 0}'), then:
    python attacks/round1_headless_signup.py [--signups 20]
"""

from playwright.sync_api import sync_playwright

from _common import bot_email, common_args, finish, new_context, report, reset, sign_up


def run(signups=20, verbose=False):
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        for i in range(signups):
            context = new_context(browser, "round1_headless_signup", i)
            results.append(sign_up(context.new_page(), bot_email(1, i)))
            context.close()
        browser.close()
    if verbose:
        report("Round 1: default headless Chromium", results)
    return results


if __name__ == "__main__":
    args = common_args(__doc__.split("\n")[1]).parse_args()
    if not args.no_reset:
        reset()
    finish("round1_headless_signup", run(args.signups, verbose=True))
