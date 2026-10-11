"""
legit_traffic.py — the other half of every round: do the defences block real
shoppers?

Drives N synthetic shoppers through the real checkout in a real browser and
checks each one still sees the "Order received" confirmation. A control that
stops the skimmer but breaks checkout has failed — that shows up here as a
blocked shopper, counted next to the bot traffic in the scoreboard.

The honest result for these controls, wired correctly, is zero user-facing
false positives: the skimmer is parasitic, and a nonce-based CSP, SRI and the
runtime monitor do not touch your own first-party checkout code. Their real
cost is operational (re-pinning SRI on every CDN bump, tuning the policy), not
blocked users — see --cdn-bump for the one place a user-facing break hides.

Run (demo store up):
    python tools/legit_traffic.py --count 10
    python tools/legit_traffic.py --cdn-bump     # show the SRI re-pin cost
"""

import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE = target("DEMO_URL", "http://127.0.0.1:5000")


def shop_once(base: str) -> dict:
    """One shopper: load checkout, submit, read the confirmation line."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(f"{base}/checkout", wait_until="networkidle")
        page.click("button[type=submit]")
        try:
            page.wait_for_function(
                "document.getElementById('result') && "
                "document.getElementById('result').textContent.length > 0",
                timeout=4000,
            )
            text = page.inner_text("#result")
            ok = "received" in text.lower()
        except Exception:
            text, ok = "(no confirmation)", False
        browser.close()
    return {"ok": ok, "result": text}


def run(base: str = BASE, count: int = 10) -> list:
    return [shop_once(base) for _ in range(count)]


def cdn_bump_cost(base: str) -> None:
    """Show the SRI false-positive: a legit vendor update now fails the pin."""
    status = json.loads(urllib.request.urlopen(f"{base}/status", timeout=5).read())
    if not status["sri"]:
        print("SRI is off, so there is no pin to break. Start with SRI=on to see this.")
        return
    print("A legitimate vendor release changes the file's bytes. Your pinned")
    print("SHA-384 no longer matches, so the browser refuses the NEW-but-good")
    print("file and that script's feature breaks for every user until you")
    print("re-run generate_sri.py and redeploy. Budget for this on each bump.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--cdn-bump", action="store_true")
    args = ap.parse_args()

    if args.cdn_bump:
        cdn_bump_cost(BASE)
        return 0

    results = run(BASE, args.count)
    broken = [r for r in results if not r["ok"]]
    print(f"=== Legitimate shoppers ({len(results)}) ===")
    for i, r in enumerate(results):
        print(f"  {'✅' if r['ok'] else '❌'} shopper {i + 1}: {r['result']}")
    print(f"\n  False positives: {len(broken)}/{len(results)} shoppers blocked")
    return 1 if broken else 0


if __name__ == "__main__":
    raise SystemExit(main())
