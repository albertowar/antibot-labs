"""
W2 Ch1 — Legitimate Traffic Simulator (Section 1.6)

Measures the other half of every defense: how many REAL users it blocks.

Each profile in tools/profiles/*.json is one kind of real visitor: the
headers their browser sends (in wire order) for the page, for fetch() and
for POST, the sensor payload their browser produces and how they click.
The simulator replays a complete shopping trip per profile, without a
browser:

    GET /               (navigation headers)  -> nonce + session cookie
    POST /api/sensor    (POST headers)        -> the profile's sensor payload
    GET /api/products   (fetch headers)
    POST /api/cart      (POST headers)        -> the profile's click

and reports blocked (403) and "suspicious" verdicts. A defense that catches
bots but blocks these users has failed.

The profiles are synthetic but grounded: header order and native-code
strings come from a real Chromium 153 capture, identity values are edited
per browser. Add your own browser with http://localhost:5000/capture: it
is saved as tools/profiles/captured-<name>.json and replayed from then on.

Trade-off: a replay is only as good as its capture. Profiles go stale as
browsers update; re-capture them whenever a rule starts depending on a new
value.

Note what this tool is: a perfect replay of a real browser's requests and
sensor payload. Round 5 shows an attacker can do exactly the same.

Run the demo site first, then:
    python tools/legit_traffic.py
"""

import glob
import http.client
import json
import os
import sys
import re
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

PROFILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")
NONCE_RE = re.compile(r'name="sensor-nonce" content="([^"]+)"')


def load_profiles():
    profiles = []
    for path in sorted(glob.glob(os.path.join(PROFILES_DIR, "*.json"))):
        with open(path) as f:
            data = json.load(f)
        data.setdefault("name", os.path.splitext(os.path.basename(path))[0])
        profiles.append(data)
    return profiles


class Replayer:
    """Sends captured headers byte-for-byte, in their original order, with a cookie jar."""

    def __init__(self, base_url=BASE_URL):
        url = urlparse(base_url)
        self.host, self.port = url.hostname, url.port or 80
        self.authority = f"{self.host}:{self.port}"
        self.cookies = {}

    def request(self, method, path, headers, body=None):
        payload = json.dumps(body).encode() if body is not None else None
        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        sent_cookie = False
        for name, value in headers:
            lower = name.lower()
            if lower == "host":
                value = self.authority
            elif lower in ("referer", "origin"):
                value = re.sub(r"//[^/]+", f"//{self.authority}", value, count=1)
            elif lower == "content-length":
                value = str(len(payload or b""))
            elif lower == "cookie":
                if not self.cookies:
                    continue
                value = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
                sent_cookie = True
            conn.putheader(name, value)
        if self.cookies and not sent_cookie:
            conn.putheader("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        conn.endheaders(payload)
        response = conn.getresponse()
        data = response.read().decode("utf-8", "replace")
        for header, value in response.getheaders():
            if header.lower() == "set-cookie":
                name, _, rest = value.partition("=")
                self.cookies[name.strip()] = rest.split(";")[0]
        timing = response.getheader("Server-Timing", "")
        conn.close()
        return response.status, data, timing


def server_ms(timing, metric):
    m = re.search(rf"{metric};dur=([\d.]+)", timing or "")
    return float(m.group(1)) if m else None


def reasons_of(status, body):
    if status != 403:
        return []
    try:
        return json.loads(body).get("reasons", [])
    except ValueError:
        return []


def replay_profile(profile, base_url=BASE_URL):
    """
    One complete shopping trip as this profile. Returns
    {profile, products, cart, verdict, score, reasons, sensor_ms, collect_ms}.
    """
    r = Replayer(base_url)
    status, html, _ = r.request("GET", "/", profile["navigation_headers"])
    out = {"profile": profile["name"], "products": status, "cart": None, "verdict": None,
           "score": None, "reasons": reasons_of(status, html), "sensor_ms": None,
           "collect_ms": (profile.get("signals") or {}).get("collect_ms"),
           "expected_cost": profile.get("expected_cost")}
    if status != 200:
        return out

    if profile.get("signals") is not None:
        nonce = NONCE_RE.search(html).group(1)
        _, _, timing = r.request("POST", "/api/sensor", profile["post_headers"],
                                 {"nonce": nonce, "signals": profile["signals"]})
        out["sensor_ms"] = server_ms(timing, "sensor")
        _, check, _ = r.request("GET", "/sensor-check", profile["fetch_headers"])
        sensor = json.loads(check).get("sensor") or {}
        out.update(verdict=sensor.get("verdict"), score=sensor.get("score"),
                   reasons=sensor.get("reasons", []))

    status, body, _ = r.request("GET", "/api/products", profile["fetch_headers"])
    out["products"] = status
    if status != 200:
        out["reasons"] = reasons_of(status, body)
        return out
    status, body, _ = r.request("POST", "/api/cart", profile["post_headers"],
                                {"product_id": 1, "interaction": profile.get("interaction")})
    out["cart"] = status
    if status != 200:
        out["reasons"] = reasons_of(status, body)
    return out


def run(base_url=BASE_URL):
    """Replay every profile. Returns one result per profile."""
    return [replay_profile(p, base_url) for p in load_profiles()]


def is_blocked(result):
    return 403 in (result["products"], result["cart"])


if __name__ == '__main__':
    results = run()
    if not results:
        print(f"No profiles found in {PROFILES_DIR}")
        raise SystemExit(1)
    print("=== Legitimate users (replayed profiles) ===")
    for r in results:
        if is_blocked(r):
            mark = "⚠️ " if r["expected_cost"] else "❌"
        else:
            mark = "🟡" if r["verdict"] == "suspicious" else "✅"
        print(f"  {mark} {r['profile']:<34} products={r['products']} cart={r['cart'] or '-'}  "
              f"sensor={r['verdict'] or '-'} ({r['score'] if r['score'] is not None else '-'})")
        for reason in r["reasons"]:
            print(f"       - {reason}")
        if r["expected_cost"] and is_blocked(r):
            print(f"       (accepted cost: {r['expected_cost']})")
    blocked = sum(is_blocked(r) for r in results)
    print(f"\n  Real users blocked: {blocked}/{len(results)}")
