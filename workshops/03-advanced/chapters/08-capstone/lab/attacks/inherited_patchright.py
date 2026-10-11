"""
Chapter 9 — Round 1 Attack: a headless Patchright farm (Section 9.7, Part 2)

Patchright is a drop-in Playwright fork that removes the automation tells
the W2 Ch1 checks look for: navigator.webdriver is false, there's no
Runtime.enable leak, and Playwright's init-script globals are gone. It
drives a real Chromium, so the JA4 is Chromium's.

Headless Chromium still names itself HeadlessChrome in the UA and in the
UA-CH brand list, so the farm rewrites both over CDP
(Emulation.setUserAgentOverride with userAgentMetadata). Every L0 check now
passes.

What it can't fix from outside the renderer: it is still a headless
browser on a server. WebGL is rendered in software (SwiftShader), the window
has no frame, and the Web Worker's navigator was never patched.

Expected results:
    DEFENSE_LEVEL 0   3/3 pairs bought
    DEFENSE_LEVEL 1+  0/3   [L1] Software WebGL, no window chrome, Worker navigator differs

Setup (once):  patchright install chromium
Run:           python attacks/inherited_patchright.py [--sessions 3]
"""

import argparse
import os
import sys

from patchright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (Cost, browser_buy, browser_register, egress_pool, farm_identity,  # noqa: E402
                     patch_headless_chromium, report, rng_for, summary, target, whoami_sid)


def run(sessions=3, verbose=False):
    base = target()
    rng = rng_for("round1")
    pool = egress_pool()
    results = []
    with Cost() as cost:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            for _ in range(sessions):
                context = browser.new_context(ignore_https_errors=True, locale="en-US",
                                              extra_http_headers={"X-Lab-Egress": rng.choice(pool)})
                page = context.new_page()
                patch_headless_chromium(context, page, browser.version)
                outcome, reasons = browser_register(page, base, farm_identity(rng))
                if outcome == "allow":
                    outcome, reasons = browser_buy(page, base)
                results.append({"outcome": outcome, "reasons": reasons, "bought": outcome == "allow",
                                "sid": whoami_sid(page, base)})
                context.close()
            browser.close()
    s = summary("inherited_patchright", results, cost)
    if verbose:
        report(s)
    return s


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=3)
    run(parser.parse_args().sessions, verbose=True)
