"""
Chapter 9 — Round 2 Attack: Camoufox, native fingerprint spoofing (Section 9.7, Part 3)

Camoufox is a Firefox build that spoofs fingerprint attributes in C++, not
in page JavaScript. Every launch gets a fresh, internally consistent device
from BrowserForge's real-world distributions: OS, screen, window frame, GPU
strings, fonts, cores. The page, its Web Workers and the HTTP headers all
agree, and the TLS stack really is Firefox's NSS. None of the L1 coherence
checks has anything to find.

What it still does by default is behave like a script: go straight to the
product, click Buy the instant the page loads. Playwright's click moves the
cursor to the button in one step.

Expected results:
    DEFENSE_LEVEL 0–1   3/3 pairs bought
    DEFENSE_LEVEL 2+    0/3   [L2] Buy click with 1 pointer moves before it, bought < 1000 ms after page load

Setup (once):  python -m camoufox fetch
Run:           python attacks/round2_camoufox.py [--sessions 3]
"""

import argparse
import os
import sys

from camoufox.sync_api import Camoufox

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (Cost, browser_buy, browser_register, egress_pool, farm_identity, report,  # noqa: E402
                     rng_for, summary, target, whoami_sid)


def run(sessions=3, verbose=False):
    base = target()
    rng = rng_for("round2")
    pool = egress_pool()
    results = []
    with Cost() as cost:
        for _ in range(sessions):
            # One launch per session: Camoufox picks a new device fingerprint per launch.
            with Camoufox(headless=True, os=rng.choice(["windows", "macos"])) as browser:
                context = browser.new_context(ignore_https_errors=True,
                                              extra_http_headers={"X-Lab-Egress": rng.choice(pool)})
                page = context.new_page()
                outcome, reasons = browser_register(page, base, farm_identity(rng))
                if outcome == "allow":
                    outcome, reasons = browser_buy(page, base)
                results.append({"outcome": outcome, "reasons": reasons, "bought": outcome == "allow",
                                "sid": whoami_sid(page, base)})
    s = summary("round2_camoufox", results, cost)
    if verbose:
        report(s)
    return s


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=3)
    run(parser.parse_args().sessions, verbose=True)
