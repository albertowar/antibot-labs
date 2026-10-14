"""
Chapter 9, Round 2 attack: scripted Camoufox, native fingerprint spoofing (Section 9.7).

Camoufox is a Firefox build that spoofs fingerprint attributes in C++, not in page JavaScript. Every launch
gets a fresh, internally consistent device from BrowserForge's real-world distributions: OS, screen, window
frame, GPU strings, fonts, cores. The page, its Web Workers and the HTTP headers all agree, and the TLS stack
really is Firefox's NSS. Nothing in W2 Ch1's coherence layer has anything to find.

What it still does by default is behave like a script: go straight to the drop, fill the form with
page.fill() (no key events) and click Reserve the instant the page loads, with one straight pointer move.

Expected:
    level 0 to 2   reserved
    level 3 and up blocked: behavior_l1 (teleport, no keystrokes, too fast) + flow (bought < 1.5 s after the page)

Setup (once):  python -m camoufox fetch
Run:           python attacks/round2_camoufox.py [--sessions 2]
"""

import argparse

from camoufox.sync_api import Camoufox

from _common import CLAIM, FIELDS, SELECTOR, Cost, browser_ctx, farm_identity, finish, open_drop, refused, report, rng_for, submit


def run(sessions=2, verbose=False):
    rng = rng_for("round2")
    results = []
    with Cost() as cost:
        for k in range(sessions):
            # One launch per session: Camoufox picks a new device fingerprint per launch.
            with Camoufox(headless=True, os=rng.choice(["windows", "macos"])) as browser:
                ctx = browser_ctx(browser, "bot:round2_camoufox", CLAIM["gecko"])
                page = ctx.new_page()
                who = farm_identity(rng)
                result = refused(open_drop(page))
                if result is None:
                    for field in FIELDS:
                        page.fill(SELECTOR[field], who[field])
                    result = submit(page, lambda: page.click(SELECTOR["reserve"]))
                results.append(result)
                if verbose:
                    report(f"round2_camoufox #{k + 1}", results[-1])
    return results, cost


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=2)
    print("=== Round 2: scripted Camoufox ===")
    results, cost = run(ap.parse_args().sessions, verbose=True)
    finish("round2_camoufox", results, cost)
