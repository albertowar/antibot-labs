"""
Chapter 2 — Legitimate Traffic Simulator (Section 2.7)

Measures the other half of every defense: what it costs REAL users.

Real users here are real browser engines driven by Playwright, browsing the
HTML store page by page (/?page=N) exactly as a person clicking "Next" would.
They run every challenge for real: no shortcuts, no injected cookies.

  chromium-1..3     ordinary visitors, 10 pages each
  chromium-slow     6x CPU throttling (CDP): a budget phone or an old laptop
  firefox           SpiderMonkey instead of V8 (skipped if not installed)
  power-user        60 pages in one session: a real person, just a busy one
  no-js             a real browser with JavaScript disabled (NoScript, Tor "Safest")

For each user: pages that loaded, challenges solved, challenges that FAILED
(a real browser failing our challenge is a false positive, full stop), and the
client-side solve time the challenge reports.

The no-js user is reported separately. Every JS challenge blocks it by
design. That isn't a bug in the challenge, it's a policy decision you have
to make on purpose (fallback page, CAPTCHA, allowlist). It's never "0".

Trade-off: Playwright's headless Chromium is a real engine, so it passes the
challenge exactly like a real Chrome does. It can't tell you about the
humans you'd lose to automation-artefact checks (W2 Ch1) or behavioural
checks (W2 Ch3). Those get their own simulators.

Run the demo site first, then:
    python tools/legit_traffic.py
"""

import os
import sys
import statistics
import time

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

# (name, engine, pages, cpu_throttle, javascript)
USERS = [
    ("chromium-1", "chromium", 10, None, True),
    ("chromium-2", "chromium", 10, None, True),
    ("chromium-3", "chromium", 10, None, True),
    ("chromium-slow", "chromium", 5, 6, True),
    ("firefox", "firefox", 5, None, True),
    ("power-user", "chromium", 60, None, True),
    ("no-js", "chromium", 3, None, False),
]


def browse(browser, name, pages, throttle, javascript):
    context = browser.new_context(java_script_enabled=javascript)
    page = context.new_page()
    stats = {"user": name, "pages_ok": 0, "pages_total": pages, "challenges_ok": 0,
             "challenges_failed": 0, "fail_reasons": [], "solve_ms": [], "elapsed_ms": [],
             "interstitial_ms": [], "nojs": not javascript}
    nav = {"start": 0.0, "challenged": False}

    def on_response(response):
        if response.url.endswith("/challenge/new"):
            nav["issued_at"] = response.request.timing["startTime"]
        if response.url.endswith("/challenge/verify"):
            body = response.request.post_data_json or {}
            nav["challenged"] = True
            if response.status == 200:
                stats["challenges_ok"] += 1
                stats["solve_ms"].append(body.get("solve_ms", 0))
                # browser-side time from asking for a challenge to sending the answer:
                # script download + parse + run. This is what obfuscation inflates.
                if "issued_at" in nav:
                    stats["elapsed_ms"].append(response.request.timing["startTime"] - nav["issued_at"])
            else:
                stats["challenges_failed"] += 1
                try:
                    stats["fail_reasons"].append(response.json().get("reason"))
                except Exception:   # the page may already be gone
                    stats["fail_reasons"].append(f"HTTP {response.status}")

    page.on("response", on_response)
    if throttle:
        page.context.new_cdp_session(page).send("Emulation.setCPUThrottlingRate", {"rate": throttle})

    timeout = 15000 if javascript else 3000
    for n in range(1, pages + 1):
        nav.update(start=time.perf_counter(), challenged=False)
        try:
            page.goto(f"{BASE_URL}/?page={n}")
            page.wait_for_selector(f'#products[data-page="{n}"]', timeout=timeout)
            stats["pages_ok"] += 1
            if nav["challenged"]:
                # what the user sat through: interstitial + challenge + reload
                stats["interstitial_ms"].append((time.perf_counter() - nav["start"]) * 1000)
        except PlaywrightError:
            pass
    context.close()
    return stats


def run(skip_firefox=False):
    """Browse as every user. Returns one stats dict per user that ran."""
    results = []
    with sync_playwright() as p:
        browsers = {"chromium": p.chromium.launch()}
        if not skip_firefox:
            try:
                browsers["firefox"] = p.firefox.launch()
            except PlaywrightError:
                print("  ⚠️  Firefox not installed (`playwright install firefox`); skipping that user")
        for name, engine, pages, throttle, javascript in USERS:
            if engine in browsers:
                results.append(browse(browsers[engine], name, pages, throttle, javascript))
        for b in browsers.values():
            b.close()
    return results


def print_report(results):
    for r in results:
        if r["nojs"]:
            mark = "⚠️ " if r["pages_ok"] < r["pages_total"] else "✅"
        else:
            mark = "✅" if r["pages_ok"] == r["pages_total"] and not r["challenges_failed"] else "❌"
        solve = (f"challenge->answer {statistics.median(r['elapsed_ms']):.0f} ms, "
                 f"interstitial {statistics.median(r['interstitial_ms']):.0f} ms"
                 if r["interstitial_ms"] else "")
        print(f"  {mark} {r['user']:<14} {r['pages_ok']:>2}/{r['pages_total']:<2} pages  "
              f"challenges ok={r['challenges_ok']} failed={r['challenges_failed']}  {solve}")
        for reason in sorted(set(r["fail_reasons"])):
            print(f"       - {reason}")


if __name__ == '__main__':
    t0 = time.perf_counter()
    results = run()
    print(f"=== Legitimate users -> {BASE_URL} ===")
    print_report(results)
    js_users = [r for r in results if not r["nojs"]]
    hurt = sum(r["pages_ok"] < r["pages_total"] or r["challenges_failed"] > 0 for r in js_users)
    print(f"\n  False positives: {hurt}/{len(js_users)} JavaScript-enabled users hurt "
          f"({time.perf_counter() - t0:.0f} s)")
