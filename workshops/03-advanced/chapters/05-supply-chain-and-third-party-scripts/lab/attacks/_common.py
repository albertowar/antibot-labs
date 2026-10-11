"""
Shared helpers for the Round attacks.

Every attack drives a real browser (Playwright) to the local checkout page,
submits synthetic card data, and then asks the local collector whether anything
got out. The attack itself is identical each round — a victim simply checks
out. What changes is the skimmer technique (set on the server via
SKIMMER_VARIANT) and the defence you have added.

Ethics guardrail: these refuse any target that is not loopback.
"""

import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE = target("DEMO_URL", "http://127.0.0.1:5000")
COLLECTOR = target("COLLECTOR_URL", "http://127.0.0.1:5001")
ensure_local = require_local


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


def reset_collector() -> None:
    try:
        urllib.request.urlopen(f"{COLLECTOR}/reset", timeout=5).read()
    except OSError:
        pass


def captured() -> dict:
    try:
        return _get_json(f"{COLLECTOR}/captured")
    except OSError:
        return {"total": 0, "sensitive": 0, "items": []}


def server_status() -> dict:
    return _get_json(f"{BASE}/status")


def drive_checkout(base: str) -> None:
    """Load the checkout page and submit the form, in a real browser."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(f"{base}/checkout", wait_until="networkidle")
        page.click("button[type=submit]")
        page.wait_for_timeout(600)          # let beacons / pixels fire
        page.goto(f"{base}/", wait_until="networkidle")  # unload flushes sendBeacon
        page.wait_for_timeout(300)
        browser.close()


def run(base: str = BASE) -> dict:
    """Reset, drive one victim checkout, return what the collector captured."""
    ensure_local(base)
    reset_collector()
    drive_checkout(base)
    return captured()


def report(label: str, base: str = BASE) -> int:
    status = server_status()
    print(f"=== {label} ===")
    print(f"  server: CSP_MODE={status['csp_mode']} SRI={status['sri']} "
          f"MONITOR={status['monitor']} VARIANT={status['skimmer_variant']}")
    result = run(base)
    if result["sensitive"]:
        print(f"  🔴 EXFIL SUCCEEDED — {result['sensitive']} capture(s) with card/password data")
        for item in result["items"][:3]:
            print(f"       via {item['via']}: {sorted(item['fields'])}")
    else:
        print(f"  🟢 nothing sensitive reached the collector "
              f"(total pings: {result['total']})")
    return 0 if not result["sensitive"] else 1
