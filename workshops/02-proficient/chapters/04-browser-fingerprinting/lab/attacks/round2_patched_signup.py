"""
Chapter 4 — Round 2 Attack: Stealth-Patched Headless Browser (Section 4.7)

Objective: get past L1 by lying. Playwright's user_agent option rewrites the
User-Agent everywhere (header, navigator, worker) and even derives a
Windows Sec-CH-UA-Platform. An init script (data/stealth_patch.js) then
patches what the page can read: navigator.platform/cores/memory, the WebGL
renderer (no more SwiftShader), the HeadlessChrome brand and the empty
voice list. Every patch is a Proxy, so "is this function native?" checks
pass.

Expected results:
  - DEFENSE_LEVEL<=1: 20/20 created (L1 sees an NVIDIA GPU and three voices)
  - DEFENSE_LEVEL>=2: 0/20, e.g.
      [L2] fingerprint_mismatch: page and worker disagree on platform ...
      [L2] fingerprint_mismatch: renderer claims hardware GPU but MAX_TEXTURE_SIZE=8192
      [L2] fingerprint_mismatch: userAgentData vs Sec-CH-UA: brands ...

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=1 python app.py
Then:
    python attacks/round2_patched_signup.py [--signups 20]
"""

import argparse
import os

from playwright.sync_api import sync_playwright

from _lab import bot_email, lab_ip, report, require_local, sign_up

PATCH = os.path.join(os.path.dirname(__file__), "data", "stealth_patch.js")


def run(signups=20, verbose=False):
    require_local()
    results = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        major = browser.version.split(".")[0]
        ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36")
        for i in range(signups):
            context = browser.new_context(
                user_agent=ua, locale="en-US", viewport={"width": 1920, "height": 969},
                screen={"width": 1920, "height": 1080},
                extra_http_headers={"X-Lab-Client-IP": lab_ip(i)})
            context.add_init_script(path=PATCH)
            results.append(sign_up(context.new_page(), bot_email(2, i)))
            context.close()
        browser.close()
    if verbose:
        report("Round 2: Proxy-patched headless Chromium", results)
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--signups", type=int, default=20)
    run(parser.parse_args().signups, verbose=True)
