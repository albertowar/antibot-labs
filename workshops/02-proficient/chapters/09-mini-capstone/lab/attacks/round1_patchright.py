"""
Chapter 9, Round 1 attack: a headless Patchright farm (Section 9.7).

Patchright is a drop-in Playwright fork that removes the automation tells W2 Ch1's first layer looks for:
navigator.webdriver is false, there is no Runtime.enable leak, and Playwright's init-script globals are gone.
It drives a real Chromium, so its TLS stack is Chromium's. Headless Chromium still names itself HeadlessChrome
in the UA and in the UA-CH brand list, so the farm rewrites both over CDP (Emulation.setUserAgentOverride with
userAgentMetadata). Every Round 0 check now passes.

What it cannot fix from outside the renderer: it is still a headless browser on a server. WebGL renders in
software (SwiftShader), the window has no frame, the page's plugins and window.chrome are what headless
Chromium has, and the CDP override reached the page but not its Web Workers (W2 Ch1 layers 2 and 3).

Expected:
    level 0, 1 (no sensor-coherence layer)   reserved
    level 2 and up                           blocked: consistency + lie_detection

Setup (once):  python -m patchright install chromium
Run:           python attacks/round1_patchright.py [--sessions 2]
"""

import argparse

from patchright.sync_api import sync_playwright

from _common import CLAIM, FIELDS, SELECTOR, Cost, browser_ctx, farm_identity, finish, open_drop, refused, report, rng_for, submit


def patch_headless_chromium(context, page, browser_version):
    """What a headless farm does after the first ban: rewrite the UA and the UA-CH metadata so neither says HeadlessChrome."""
    major = browser_version.split(".")[0]
    ua = (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
          f"Chrome/{major}.0.0.0 Safari/537.36")
    brands = [{"brand": "Chromium", "version": major}, {"brand": "Google Chrome", "version": major},
              {"brand": "Not_A Brand", "version": "8"}]
    cdp = context.new_cdp_session(page)
    cdp.send("Emulation.setUserAgentOverride", {
        "userAgent": ua, "acceptLanguage": "en-US,en;q=0.9", "platform": "Win32",
        "userAgentMetadata": {"brands": brands, "fullVersionList": brands, "platform": "Windows",
                              "platformVersion": "15.0.0", "architecture": "x86", "model": "",
                              "mobile": False, "bitness": "64"}})


def run(sessions=2, verbose=False):
    rng = rng_for("round1")
    results = []
    with Cost() as cost:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            for k in range(sessions):
                ctx = browser_ctx(browser, "bot:round1_patchright", CLAIM["chromium"], locale="en-US",
                                  viewport={"width": 1280, "height": 720})
                page = ctx.new_page()
                patch_headless_chromium(ctx, page, browser.version)
                who = farm_identity(rng)
                result = refused(open_drop(page))
                if result is None:
                    for field in FIELDS:
                        page.fill(SELECTOR[field], who[field])
                    result = submit(page, lambda: page.click(SELECTOR["reserve"]))
                results.append(result)
                if verbose:
                    report(f"round1_patchright #{k + 1}", results[-1])
                ctx.close()
            browser.close()
    return results, cost


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=2)
    print("=== Round 1: headless Patchright ===")
    results, cost = run(ap.parse_args().sessions, verbose=True)
    finish("round1_patchright", results, cost)
