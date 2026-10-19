"""
cdn_bump.py: the operational cost of SRI, measured.

Subresource Integrity is a promise about one file's bytes. When the vendor ships a legitimate new
release the bytes change, the pinned hash no longer matches, and the browser refuses the NEW, GOOD
file for every visitor until you re-pin and redeploy. Nothing is attacking you; your control fails
closed. This visits the store as a customer would, three times, with the vendor serving:

    clean        the release you pinned          -> loads when SRI is on
    updated      a legitimate new release (2.4.0) -> REFUSED when SRI is on (the false positive)
    compromised  the swapped file                -> REFUSED when SRI is on (the control working)

and reports whether the vendor script actually ran (window.AnalyticsHelper). With SRI off, all three
run, including the skimmer. Run it with the store at level 3 or 4 to see the trade.

    python tools/cdn_bump.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402  (runs the labnet guard)
from labclient import BASE_URL, admin  # noqa: E402


def probe(base=BASE_URL):
    """{vendor state: did the vendor script run?}. Leaves the store serving the compromised file."""
    from playwright.sync_api import sync_playwright
    out = {}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for vendor in ("clean", "updated", "compromised"):
            admin("POST", "/lab/supply/scenario", json={"vendor": vendor, "variant": "beacon"})
            ctx = labclient.browser_context(browser, "human:probe:00")
            page = ctx.new_page()
            page.goto(f"{base}/login", wait_until="load")
            out[vendor] = bool(page.evaluate("typeof window.AnalyticsHelper !== 'undefined'"))
            ctx.close()
        browser.close()
    admin("POST", "/lab/supply/scenario", json={"vendor": "compromised"})
    return out


def main():
    st = admin("GET", "/lab/supply/status")
    sri = st["controls"]["sri"]
    res = probe()
    print(f"store at level {st['level']}, SRI {'on' if sri else 'off'}: did the vendor script run?")
    for vendor, ran in res.items():
        print(f"  vendor serves {vendor:<12} {'ran' if ran else 'REFUSED by the browser'}")
    if sri and not res["updated"]:
        print("\nThe 'updated' line is the cost: a legitimate release is refused for every visitor until you re-pin\n"
              "(python -m defenses.generate_sri) and redeploy. Budget for that on every vendor update.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
