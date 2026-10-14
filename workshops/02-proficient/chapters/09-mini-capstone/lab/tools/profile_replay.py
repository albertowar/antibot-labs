"""
Chapter 1: replay a real browser's shopping trip from a profile, without a browser.

Each tools/profiles/*.json is one kind of real visitor: the headers its browser sends (in wire
order) for a page, for fetch() and for a POST, the sensor report its browser produces, and how
it clicks. A trip is what the store's Quick add panel makes a browser do:

    GET  /                  (navigation headers)  -> the session cookie and the sensor nonce
    POST /api/telemetry     (POST headers)        -> {"kind": "sensor", nonce, the profile's signals}
    GET  /api/products      (fetch headers)
    POST /api/cart/add      (POST headers)        -> the first product, with the profile's click

Two users of this module:
    tools/personas_ch1.py           the 40 shoppers: each one replays the profile of its kind of browser
    attacks/round5_forged_sensor.py the attacker: the same replay is a perfect forgery (Round 5)

The profiles are synthetic but grounded: header order and native-code strings come from a real
Chromium 153 capture, identity values are edited per browser. Add your own browser with
http://127.0.0.1:5000/lab/capture; it is saved as tools/profiles/captured-<name>.json and replayed
from then on.

Trade-off: a replay is only as good as its capture. Profiles go stale as browsers update; re-capture
them whenever a rule starts depending on a new value.
"""

import glob
import json
import os
import re

from labclient import BASE_URL

PROFILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")
NONCE_RE = re.compile(r"ShopSensor\.send\(\"([^\"]+)\"\)")
AUTHORITY = re.sub(r"^https?://", "", BASE_URL).rstrip("/")


def load_profiles():
    profiles = []
    for path in sorted(glob.glob(os.path.join(PROFILES_DIR, "*.json"))):
        with open(path) as f:
            data = json.load(f)
        data.setdefault("name", os.path.splitext(os.path.basename(path))[0])
        profiles.append(data)
    return profiles


def profile(name):
    return next(p for p in load_profiles() if p["name"] == name)


def headers(client, captured):
    """
    The captured headers, in their captured order, fixed for this store: no Host (the client adds
    it first, as browsers do), Origin and Referer pointed here, and the Cookie slot kept in place
    with this session's cookies (requests fills in the value), or dropped before the first response.
    """
    out = []
    for name, value in captured:
        lower = name.lower()
        if lower == "host":
            continue
        if lower in ("origin", "referer"):
            value = re.sub(r"//[^/]+", f"//{AUTHORITY}", value, count=1)
        elif lower == "cookie":
            if not client.http.cookies:
                continue
            value = "; ".join(f"{c.name}={c.value}" for c in client.http.cookies)
        elif lower == "content-length":
            value = "0"                       # requests sets the real length, in this slot
        out.append((name, value))
    return out


def _signals(r):
    return r.headers.get("X-Lab-Signals", "")


def trip(client, prof):
    """
    One shopping trip as `prof`, through `client` (a labclient.LabClient). Returns
    {profile, page, products, cart, signals, score, gate_ms}: HTTP statuses (None where the trip
    stopped), the highest X-Lab-Score of the API calls, and the gate's time on /api/products.
    """
    out = {"profile": prof["name"], "page": None, "products": None, "cart": None, "signals": "", "score": 0,
           "gate_ms": None}
    r = client.get("/", headers(client, prof["navigation_headers"]))
    out["page"] = r.status_code
    if r.status_code != 200:
        out["signals"] = _signals(r)
        return out
    m = NONCE_RE.search(r.text)
    if prof.get("signals") is not None and m:          # a browser with JavaScript runs the sensor
        client.post("/api/telemetry", headers=headers(client, prof["post_headers"]),
                    json={"kind": "sensor", "nonce": m.group(1), "signals": prof["signals"]})
    r = client.get("/api/products?sort=rating", headers(client, prof["fetch_headers"]))
    out["products"], out["signals"] = r.status_code, _signals(r)
    out["score"] = int(r.headers.get("X-Lab-Score") or 0)
    timing = re.search(r"gate;dur=([\d.]+)", r.headers.get("Server-Timing", ""))
    out["gate_ms"] = float(timing.group(1)) if timing else None
    if r.status_code != 200:
        return out
    item = r.json()["items"][0]
    r = client.post("/api/cart/add", headers=headers(client, prof["post_headers"]),
                    json={"sku": item["sku"], "size": (item.get("sizes") or [""])[0], "qty": 1,
                          "interaction": prof.get("interaction")})
    out["cart"] = r.status_code
    out["score"] = max(out["score"], int(r.headers.get("X-Lab-Score") or 0))
    if r.status_code != 200:
        out["signals"] = _signals(r)
    return out
