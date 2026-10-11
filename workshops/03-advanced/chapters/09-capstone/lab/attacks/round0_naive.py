"""
Chapter 9 — Round 0 Attack: the naive fleet (Section 9.7, Part 1)

Three cheap bots that the end-of-Ch8 stack (DEFENSE_LEVEL 0) already stops.
Run them once so you have seen every L0 layer fire:

    requests        python-requests UA + OpenSSL TLS     -> [L0] UA red flag / TLS stack mismatch
    curl_cffi       Chrome TLS + headers, but no JS      -> [L0] No telemetry from the drop page
    playwright      stock headless Chromium              -> [L0] HeadlessChrome, no Accept-Language

Expected: 0 pairs bought at every DEFENSE_LEVEL.

Run (store running):
    python attacks/round0_naive.py
"""

import os
import sys

import requests
from curl_cffi import requests as cffi
from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (DROP, Cost, browser_buy, browser_register, egress_pool, farm_identity, report,  # noqa: E402
                     rng_for, summary, target, whoami_sid)


def http_bot(session, base, ident, egress):
    """Register, open the product page, buy: all over bare HTTP, no JavaScript."""
    headers = {"X-Lab-Egress": egress}
    r = session.post(f"{base}/api/register", json=ident, headers=headers)
    if r.status_code == 403:
        return {"outcome": "block", "reasons": r.json().get("reasons", []), "bought": False}
    session.get(f"{base}{DROP}", headers=headers)
    r = session.post(f"{base}/api/buy", json={"sku": "lab-runner-9"}, headers=headers)
    body = r.json()
    sid = session.get(f"{base}/whoami", headers=headers).json().get("sid")
    return {"outcome": body.get("outcome"), "reasons": body.get("reasons", []),
            "bought": body.get("outcome") == "allow", "sid": sid}


def run(verbose=False):
    base = target()
    rng = rng_for("round0")
    pool = egress_pool()
    results = []
    with Cost() as cost:
        s = requests.Session()
        s.verify = False
        results.append({"bot": "requests", **http_bot(s, base, farm_identity(rng), "192.0.2.10")})

        s = cffi.Session(impersonate="chrome150", verify=False)
        results.append({"bot": "curl_cffi", **http_bot(s, base, farm_identity(rng), rng.choice(pool))})

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True,
                                          extra_http_headers={"X-Lab-Egress": rng.choice(pool)})
            page = context.new_page()
            outcome, reasons = browser_register(page, base, farm_identity(rng))
            if outcome == "allow":
                outcome, reasons = browser_buy(page, base)
            results.append({"bot": "playwright", "outcome": outcome, "reasons": reasons,
                            "bought": outcome == "allow", "sid": whoami_sid(page, base)})
            browser.close()
    s = summary("round0_naive", results, cost)
    if verbose:
        report(s)
        for r in results:
            print(f"  {r['bot']:<11} {r['outcome']:<9} {r['reasons'][:2]}")
    return s


if __name__ == '__main__':
    run(verbose=True)
