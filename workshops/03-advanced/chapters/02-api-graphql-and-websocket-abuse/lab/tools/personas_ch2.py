"""
W3 Ch2's shoppers: the starter's 40 people, now holding an API client.

The same 40 personas, each using the store through the surface a real customer of that kind would:

    role      who                              what they do                                          surface
    --------  -------------------------------  ----------------------------------------------------  ----------------
    browser   everyone not listed below (28)   the catalogue page, three products they picked, the   REST + persisted
                                               reviews page, the storefront's persisted GraphQL      GraphQL
    app       mobile_cgnat (8, 2 shared IPs)   open the app (catalogue), log in, SIGNED orders and   REST + signed
                                               inventory reads, the persisted AccountOrders query    reads + GraphQL
    feed      the first four `home` (4)        open the live drop feed from our own origin,          WebSocket
                                               subscribe three times

Every client sends what its defense expects: a bearer token and a signature for the app, a trusted document for
GraphQL, our own Origin for the feed. A defense that refuses any of them is a false positive, counted as a
shopper hurt. Eight phones behind two carrier addresses are the awkward case for an address-keyed budget (the
app role keys on the bearer subject once logged in; until then it is the shared address).

Outcomes use the population vocabulary: `browsed` (finished), `blocked` (a 403/429 or a refused handshake) and
`failed` (anything else).
"""

import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import browsers  # noqa: E402
import population  # noqa: E402
from api_sdk import APP_UA, BASE_URL, ApiApp, open_feed  # noqa: E402
from demo_site.seed import password_for, username  # noqa: E402


def role_of(p):
    n = int(p.actor.rsplit(":", 1)[1])
    if p.persona == "mobile_cgnat":
        return "app"
    if p.persona == "home" and n < 4:
        return "feed"
    return "browser"


def _ua(p):
    return dict(browsers.headers_for(p.browser, "link", BASE_URL))["User-Agent"]


def _finish(p, role, app, statuses):
    bad = [s for s in statuses if s >= 400]
    outcome = "browsed" if not bad else ("blocked" if bad[-1] in (403, 429) else "failed")
    p.result.update(outcome=outcome, status=bad[-1] if bad else 200, requests=app.client.requests,
                    verdict=app.client.verdict(), role=role)
    return p.result


def scenario_browser(p, client, rng):
    time.sleep(rng.uniform(0, 3))
    app = ApiApp(p.actor, p.ip, ua=_ua(p), client=client)
    st = [app.get("/api/products?page=1").status_code]
    for n in rng.sample(range(1, 121), 3):                       # three products they picked, not in order
        time.sleep(rng.uniform(0.2, 0.8))
        st.append(app.get(f"/api/products/p{n:03d}").status_code)
    st.append(app.get("/api/v2/reviews?limit=20").status_code)
    st.append(app.persisted("Products").status_code)
    return _finish(p, "browser", app, st)


def scenario_app(p, client, rng):
    time.sleep(rng.uniform(0, 4))
    app = ApiApp(p.actor, p.ip, ua=APP_UA, client=client)
    st = [app.get("/api/products?page=1").status_code]            # the app opens on the catalogue, anonymous
    r = app.login(username(p.account), password_for(p.account))
    st.append(r.status_code)
    if r.status_code == 200:
        time.sleep(rng.uniform(0.3, 1.0))
        st.append(app.get("/api/v2/account/orders", signed=True).status_code)
        st.append(app.get(f"/api/v2/inventory/lab-runner-9", signed=True).status_code)
        st.append(app.persisted("AccountOrders").status_code)
    return _finish(p, "app", app, st)


def scenario_feed(p, client, rng):
    time.sleep(rng.uniform(0, 3))
    try:
        with open_feed(p.actor, p.ip, origin=BASE_URL, ua=_ua(p)) as ws:
            for _ in range(3):
                ws.send(json.dumps({"action": "subscribe"}))
                reply = json.loads(ws.recv(timeout=5))
                if reply.get("event") != "inventory":
                    raise RuntimeError(f"unexpected frame {reply}")
                time.sleep(0.2)
        outcome, status = "browsed", 101
    except Exception as e:                                          # a refused handshake is a 403 to the client
        refused = "403" in repr(e) or "429" in repr(e)
        outcome, status = ("blocked" if refused else "failed"), (403 if refused else 0)
    p.result.update(outcome=outcome, status=status, requests=1, verdict=None, role="feed")
    return p.result


def scenario_api(p, client, rng):
    return {"app": scenario_app, "feed": scenario_feed, "browser": scenario_browser}[role_of(p)](p, client, rng)


population.SCENARIOS["ch2_api"] = scenario_api
