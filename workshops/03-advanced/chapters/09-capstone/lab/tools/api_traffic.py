"""
Capstone — legitimate API clients (W3 Ch2, "measuring both sides")

The API-hardening layer (L5) has its own false-positive surface: a mobile app
and a partner integration are legitimate non-browser clients. If GraphQL cost
limits or JA4 token binding are too tight, you break them. This simulator runs
three honest API clients alongside the attacks so every API round reports what
the hardening did to them:

    mobile-app   logs in, gets a JA4-bound token, pages the REST catalog a few
                 times (a normal browse), well under the velocity limit
    partner-api  runs one small, shallow GraphQL query for its storefront
    mobile-app2  a second mobile client, to show the limit is per-client

Each uses curl_cffi with a real Chrome TLS stack, so its JA4 is a browser's and
its token binds correctly. A 403 on any of them is a false positive.

Run (store running):
    python tools/api_traffic.py
"""

import os
import sys

from curl_cffi import requests as cffi

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import humans  # noqa: E402
import personas  # noqa: E402
from legit_traffic import solve_challenge  # noqa: E402
from lab import BASE_URL, ensure_local  # noqa: E402

FP = {"ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15",
      "platform": "iPhone", "hc": 6, "languages": ["en-US"], "screen": [390, 844], "win": [390, 844],
      "webgl": {"vendor": "Apple", "renderer": "Apple GPU"}, "canvas": "apple-ios",
      "tz": "America/New_York", "plugins": 0, "webdriver": False, "automation_globals": []}


def _login(s, base, user, rng):
    s.get(f"{base}/login")
    fp = dict(FP, worker={"ua": FP["ua"], "platform": FP["platform"], "hc": FP["hc"], "languages": FP["languages"]})
    reply = s.post(f"{base}/api/telemetry",
                   json={"page": "/login", "fp": fp, "events": humans.typing_events(rng, 20)}).json()
    chal = s.get(f"{base}/api/challenge").json()
    counter = solve_challenge(chal["nonce"], reply["fp_hash"], chal["difficulty"])
    token = s.post(f"{base}/api/challenge/verify",
                   json={"nonce": chal["nonce"], "counter": counter}).json().get("token") or ""
    r = s.post(f"{base}/api/login", json={"email": user["email"], "password": user["password"]},
               headers={"X-Lab-Token": token})
    return r


def _result(name, stage, r):
    try:
        body = r.json()
    except ValueError:
        body = {}
    outcome = "allow" if r.status_code < 400 else ("block" if r.status_code == 403 else "error")
    return {"persona": name, "stage": stage, "outcome": outcome, "status": r.status_code,
            "reasons": body.get("reasons", body.get("errors", [])), "score": body.get("score"),
            "score_ms": None, "sid": None}


def mobile_client(base, user, pages=4):
    import random
    rng = random.Random(user["email"])
    s = cffi.Session(impersonate="safari260_ios", verify=False, timeout=20)
    device = personas.device_id(user["email"])
    s.cookies.set("did", device, domain="localhost")
    r = _login(s, base, user, rng)
    if r.status_code >= 400 or r.json().get("outcome") != "allow":
        return [_result("mobile-app", "login", r)]
    tok = s.get(f"{base}/api/token").json().get("token", "")
    out = []
    for offset in range(0, pages * 24, 24):
        rr = s.get(f"{base}/api/v1/products?limit=24&offset={offset}",
                   headers={"Authorization": f"Bearer {tok}"})
        out.append(_result("mobile-app", f"rest@{offset}", rr))
    return out


def partner_client(base, user):
    import random
    rng = random.Random("partner:" + user["email"])
    s = cffi.Session(impersonate="chrome150", verify=False, timeout=20)
    s.cookies.set("did", personas.device_id(user["email"]), domain="localhost")
    r = _login(s, base, user, rng)
    if r.status_code >= 400 or r.json().get("outcome") != "allow":
        return [_result("partner-api", "login", r)]
    rr = s.post(f"{base}/graphql", json={"query": "{ products(limit: 8) { sku name price } }"})
    return [_result("partner-api", "graphql", rr)]


def run(base_url=BASE_URL):
    ensure_local(base_url)
    users = personas.legit_users()
    out = []
    out += mobile_client(base_url, users[0])
    out += partner_client(base_url, users[1])
    out += mobile_client(base_url, users[2])
    return out


if __name__ == '__main__':
    results = run()
    blocked = [r for r in results if r["outcome"] != "allow"]
    for r in results:
        flag = "✅" if r["outcome"] == "allow" else "❌"
        print(f"  {flag} {r['persona']:<12} {r['stage']:<10} {r['outcome']:<6} {r['status']} {r['reasons'][:1]}")
    print(f"{len(results) - len(blocked)}/{len(results)} legit API calls allowed")
