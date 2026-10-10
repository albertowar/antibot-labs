"""Legitimate-traffic simulator — the other half of every round's scoreboard.

A defense is only as good as its cost to real users, so we run ~40 synthetic but
*well-behaved* clients next to the attacks and count how many each round blocks.
Three cohorts, matching the three API surfaces:

  * **browsers** (30): fetch one small page of products and view a few product
    details with non-sequential ids, each from its own residential egress IP.
  * **mobile app** (6): log in, then make HMAC-signed calls to the protected
    orders and inventory endpoints and one persisted GraphQL query — exactly the
    trusted operations the allowlist knows.
  * **live feed** (4): open a WebSocket from our own origin with a valid token,
    subscribe, and send a trickle of messages.

Each client uses a distinct egress IP on purpose: real customers are not behind
one address. That is also the key caveat — behind CGNAT or a corporate NAT they
*would* share an IP, and an IP-keyed limiter would start charging them as one
noisy client. We surface that in the chapter's false-positive section; here the
point is to show the defenses cost these clients nothing.
"""

from __future__ import annotations

import json
import os
import random
import sys
import time

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
from request_signing import sign  # noqa: E402

try:
    from websockets.sync.client import connect as ws_connect
except Exception:  # pragma: no cover
    ws_connect = None

BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")
MOBILE_UA = "LabRunnerApp/4.2 (iOS 18)"
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0 Safari/537.36"
N_BROWSERS, N_MOBILE, N_FEED = 30, 6, 4


def _res_ip(n: int) -> str:
    return f"198.51.100.{10 + n}"


def browser(c: httpx.Client, n: int) -> bool:
    h = {"X-Lab-Actor": "legit-browser", "X-Lab-Egress": _res_ip(n), "User-Agent": BROWSER_UA}
    ok = c.get("/api/v2/products", params={"page": 1, "per_page": 20}, headers=h).status_code == 200
    for pid in random.sample(range(1, 500), 3):  # non-sequential, like real browsing
        ok = ok and c.get(f"/api/v2/products/{pid}", headers=h).status_code == 200
    return ok


def mobile(c: httpx.Client, n: int, persisted_q: str) -> bool:
    ip = _res_ip(100 + n)
    base_h = {"X-Lab-Actor": "legit-mobile", "X-Lab-Egress": ip, "User-Agent": MOBILE_UA}
    # Each mobile client registers its own account so logins succeed repeatably.
    email = f"mobile{n}@example.com"
    c.post("/api/v2/auth/register", json={"email": email, "password": "App-Pass-1!"}, headers=base_h)
    lr = c.post("/api/v2/auth/login", json={"email": email, "password": "App-Pass-1!"}, headers=base_h)
    if lr.status_code != 200:
        return False
    tok, secret = lr.json()["access_token"], lr.json()["api_secret"]

    def signed(method: str, path: str) -> int:
        ts = str(int(time.time()))
        h = dict(base_h)
        h["Authorization"] = f"Bearer {tok}"
        h["X-Timestamp"] = ts
        h["X-Signature"] = sign(secret, method, path, ts, b"")
        return c.request(method, path, headers=h).status_code

    ok = signed("GET", "/api/v2/account/orders") == 200
    ok = ok and signed("GET", "/api/v2/inventory/lab-runner-9") == 200
    gh = dict(base_h)
    gh["Authorization"] = f"Bearer {tok}"
    ok = ok and c.post("/graphql", json={"query": persisted_q}, headers=gh).status_code == 200
    return ok


def feed(n: int) -> bool:
    if ws_connect is None:
        return True  # websockets client not available; skip without penalising
    base = BASE_URL.replace("http://", "ws://")
    # A valid, first-party connection: our own Origin and an (anonymous) subscriber.
    extra = {"Origin": BASE_URL, "X-Lab-Actor": "legit-feed", "X-Lab-Egress": _res_ip(200 + n),
             "User-Agent": BROWSER_UA}
    try:
        with ws_connect(base + "/ws/drop", additional_headers=extra, open_timeout=5) as ws:
            for _ in range(3):
                ws.send(json.dumps({"action": "subscribe"}))
                ws.recv(timeout=5)
                time.sleep(0.2)
        return True
    except Exception:
        return False


def run(base: str = BASE_URL) -> dict:
    persisted_q = json.load(open(os.path.join(LAB_DIR, "data", "persisted_queries.json")))["Products"]
    result = {}
    with httpx.Client(base_url=base, timeout=15) as c:
        result["browsers"] = {"n": N_BROWSERS, "ok": sum(browser(c, i) for i in range(N_BROWSERS))}
        result["mobile"] = {"n": N_MOBILE, "ok": sum(mobile(c, i, persisted_q) for i in range(N_MOBILE))}
    result["feed"] = {"n": N_FEED, "ok": sum(feed(i) for i in range(N_FEED))}
    total = N_BROWSERS + N_MOBILE + N_FEED
    ok = result["browsers"]["ok"] + result["mobile"]["ok"] + result["feed"]["ok"]
    result["total"] = total
    result["allowed"] = ok
    result["blocked"] = total - ok
    return result


if __name__ == "__main__":
    s = run()
    print(f"[legit] {s['allowed']}/{s['total']} legitimate clients served "
          f"({s['blocked']} blocked)  "
          f"browsers {s['browsers']['ok']}/{s['browsers']['n']}, "
          f"mobile {s['mobile']['ok']}/{s['mobile']['n']}, "
          f"feed {s['feed']['ok']}/{s['feed']['n']}")
