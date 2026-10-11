"""
Capstone Round 4 Attack — the integrated assault (W3, all layers)

The scalper stops playing one move at a time and runs the whole kill chain in
one session, the way a real operation does:

    1. recon     scrape the catalog over the API (GraphQL batch) to find the drop
    2. evade     poll inventory low-and-slow to stay under the rate limits
    3. purchase  buy with the best browser available

Against the full stack (DEFENSE_LEVEL 7, every layer on and tuned) each move is
answered by a different layer: L5 refuses the batch, L6 flags the machine-even
polling, and L0-L4 stop the purchase. The headline number is pairs bought,
which should be zero; the per-stage outcomes show which layer caught what — the
"kill chain" you write up in the post-incident report.

The purchase stage uses curl_cffi here (always available) and is blocked at L0
for sending no telemetry. A real integrated attack drives a stealth browser
(Camoufox); if it is installed this script uses it, otherwise it says so. That
browser path is the W2 Ch9 capstone's territory and is a bonus here.

Run (store running at DEFENSE_LEVEL 7, all round solutions applied):
    python attacks/round4_integrated.py
"""

import os
import sys
import time

from curl_cffi import requests as cffi

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import DROP, Cost, egress_pool, farm_identity, report, rng_for, summary, target  # noqa: E402


def recon_scrape(base, egress):
    s = cffi.Session(impersonate="chrome150", verify=False, timeout=15)
    s.headers.update({"X-Lab-Egress": egress})
    aliases = " ".join(f'p{i}: product(sku:"lab-runner-9"){{name price}}' for i in range(80))
    r = s.post(f"{base}/graphql", json=[{"query": "{ " + aliases + " }"}])
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    ok = isinstance(body, list) and body and "data" in body[0]
    return {"stage": "recon_scrape", "bought": False, "outcome": "allow" if ok else "block",
            "reasons": (body.get("errors", [{}])[0].get("reasons", []) if isinstance(body, dict) else []), "sid": None}


def evade_poll(base, egress, n=14, interval_s=0.35):
    s = cffi.Session(impersonate="chrome150", verify=False, timeout=15)
    s.headers.update({"X-Lab-Egress": egress})
    for _ in range(n):
        s.get(f"{base}{DROP}")
        time.sleep(interval_s)
    stream = s.get(f"{base}/whoami").json().get("stream", {})
    evaded = stream.get("points", 0) == 0
    return {"stage": "evade_poll", "bought": False, "outcome": "allow" if evaded else "block",
            "reasons": stream.get("reasons", []), "sid": s.get(f"{base}/whoami").json().get("sid")}


def purchase_curl(base, egress, rng):
    """A bare HTTP purchase: no page, no telemetry. Stopped at L0."""
    s = cffi.Session(impersonate="chrome150", verify=False, timeout=15)
    s.headers.update({"X-Lab-Egress": egress})
    ident = farm_identity(rng)
    r = s.post(f"{base}/api/register", json=ident)
    if r.status_code == 403:
        return {"stage": "purchase", "tool": "curl_cffi", "bought": False, "outcome": "block",
                "reasons": r.json().get("reasons", []), "sid": None}
    s.get(f"{base}{DROP}")
    r = s.post(f"{base}/api/buy", json={"sku": "lab-runner-9"})
    body = r.json()
    return {"stage": "purchase", "tool": "curl_cffi", "bought": body.get("outcome") == "allow",
            "outcome": body.get("outcome"), "reasons": body.get("reasons", []),
            "sid": s.get(f"{base}/whoami").json().get("sid")}


def purchase_camoufox(base, rng):
    """Optional stealth-browser purchase. Skipped cleanly if Camoufox is absent."""
    try:
        from camoufox.sync_api import Camoufox
    except Exception:
        return None
    try:
        from _common import browser_buy, browser_register
        with Camoufox(headless=True, humanize=True) as browser:
            page = browser.new_page()
            ident = farm_identity(rng)
            outcome, reasons = browser_register(page, base, ident, type_delay=40)
            if outcome == "allow":
                outcome, reasons = browser_buy(page, base)
            return {"stage": "purchase", "tool": "camoufox", "bought": outcome == "allow",
                    "outcome": outcome, "reasons": reasons, "sid": None}
    except Exception as exc:
        return {"stage": "purchase", "tool": "camoufox", "bought": False, "outcome": "error",
                "reasons": [str(exc)], "sid": None}


def run(verbose=False):
    base = target()
    rng = rng_for("round4")
    pool = egress_pool()
    with Cost() as cost:
        results = [recon_scrape(base, rng.choice(pool)), evade_poll(base, rng.choice(pool)),
                   purchase_curl(base, rng.choice(pool), rng)]
        cfx = purchase_camoufox(base, rng)
        if cfx is not None:
            results.append(cfx)
    s = summary("round4_integrated", results, cost, success_key="bought")
    if verbose:
        report(s, success_label="pairs bought")
        for r in results:
            print(f"  {r['stage']:<14} {r.get('tool',''):<10} {r['outcome']:<6} {r['reasons'][:2]}")
    return s


if __name__ == '__main__':
    run(verbose=True)
