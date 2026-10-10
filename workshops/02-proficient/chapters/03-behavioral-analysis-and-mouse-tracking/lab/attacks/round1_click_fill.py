"""
Chapter 3, Round 1 attack: the default Playwright scalper (Section 3.3).

What most automation looks like out of the box: page.click() teleports the
mouse to the exact centre of the element in one step, page.fill() inserts
the text with no key events, and the whole form is done in a few hundred
milliseconds. Every header and fingerprint is a real Chromium's; only the
behavior gives it away.

Expected (verified with Playwright 1.63 / Chromium):
    DEFENSE_LEVEL 0     reserved
    DEFENSE_LEVEL >= 1  blocked: too fast + teleport + centre + text without keys + (0, 0)

Run the demo site first, then:
    python attacks/round1_click_fill.py
"""

from playwright.sync_api import sync_playwright

from common import identity, open_drop, report, wait_result


def run(verbose=False):
    with sync_playwright() as p:
        browser, page = open_drop(p, "round1_click_fill")
        who = identity()
        page.fill("#name", who["name"])
        page.fill("#email", who["email"])
        page.fill("#size", who["size"])
        page.click("#reserve")
        result = wait_result(page)
        browser.close()
    if verbose:
        report("round1_click_fill", result)
    return [result]


if __name__ == "__main__":
    print("=== Round 1: page.fill() + page.click() ===")
    run(verbose=True)
