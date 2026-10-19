"""
Chapter 2, Round 0: recon (Section 2.7).

Objective: before attacking, look at what the store's collector sees from a default Playwright
Chromium, and compare it with your own browser on http://127.0.0.1:5000/lab/fp/check.

Nothing is created: /lab/fp/check only collects and judges.

Run the store first (any level):  python demo_site/app.py
Then:
    python attacks/round0_recon.py
"""

import json

from playwright.sync_api import sync_playwright

from _common import BASE_URL, new_context

FIELDS = [
    ("User-Agent", lambda p: p["nav"]["userAgent"]),
    ("userAgentData brands", lambda p: ", ".join((p.get("uad") or {}).get("brands", []))),
    ("WebGL renderer", lambda p: p["webgl"].get("unmaskedRenderer")),
    ("MAX_TEXTURE_SIZE", lambda p: p["webgl"].get("maxTextureSize")),
    ("Canvas hash (x2)", lambda p: f"{p['canvas']['hash']} / {p['canvas']['hash2']}"),
    ("Audio sum", lambda p: p["audio"].get("sum")),
    ("Fonts found", lambda p: f"{len(p['fonts'])}: {', '.join(p['fonts'])}"),
    ("Speech voices", lambda p: p["voices"]["count"]),
    ("Screen", lambda p: f"{p['screen']['width']}x{p['screen']['height']} @{p['screen']['devicePixelRatio']}"),
    ("Cores / memory", lambda p: f"{p['nav']['hardwareConcurrency']} / {p['nav']['deviceMemory']}"),
    ("Worker platform", lambda p: p["worker"].get("platform")),
    ("Collector time", lambda p: f"{p['collect_ms']} ms"),
]


def run(verbose=True):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = new_context(browser, "round0_recon", 0).new_page()
        page.goto(f"{BASE_URL}/lab/fp/check")
        page.wait_for_function("window.__fpResult !== undefined", timeout=15000)
        me = page.evaluate("fetch('/lab/fp/me').then(r => r.json())")
        browser.close()
    if verbose:
        print("=== Round 0: what the store sees from Playwright's default Chromium ===\n")
        for name, get in FIELDS:
            print(f"  {name:<22} {get(me['payload'])}")
        print(f"\n  device_class {me['device_class']}   fp_id {me['fp_id']}\n")
        print("  How each level would judge it:")
        for level, r in me["levels"].items():
            print(f"    L{level}: {r['verdict']:<8} score={r['score']:<3} {r['reasons'][:1]}")
    return me


if __name__ == "__main__":
    me = run()
    print(json.dumps({"attack": "round0_recon", "attempted": 1, "succeeded": 1, "device_class": me["device_class"]}))
