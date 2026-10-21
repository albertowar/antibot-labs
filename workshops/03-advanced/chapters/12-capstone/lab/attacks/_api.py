"""
Shared helpers for the Workshop 3 attacks (Rounds 1 to 4): API clients that look like Chrome on the wire.

Every script imports _common (the W2 Ch9 helpers, which import tools/labclient.py and so run the labnet localhost
guard) and builds its HTTP client here. The attackers are `curl_cffi` impersonating Chrome 150: a perfect browser
ClientHello and header set, none of a browser's JavaScript. That is the attacker Round 0 cannot see through at the
request (level 1's TLS and header checks pass) and the one the API layer has to stop by shape and rate. Like every
client of this lab they CLAIM their TLS stack in `X-Lab-JA4` (the store sits behind no TLS edge) and rent their
source address from data/world.json.

Every attack prints, as its last line, one JSON object for tools/checkpoint.py: {"attempted": n, "succeeded": k}.
`succeeded` means the technique got what it wanted (a scraped catalogue, a flooded socket, an exfiltrated field);
it is the number each round drives to zero.
"""

import json

from curl_cffi import requests as cffi

from _common import BASE_URL, CLAIM, Cost, bot_ip, outcome, rng_for  # noqa: F401  (re-exported)

SKUS = ["lab-runner-9", "lab-hoodie-1", "p001", "p002"]
DROP = "/drop/lab-runner-9"


def lab_headers(actor, ip):
    """The simulated edge's inputs: the rented address, the label for the scoreboard, the claimed TLS stack."""
    return {"X-Lab-Client-IP": ip, "X-Lab-Actor": actor, "X-Lab-JA4": CLAIM["chromium"]}


class Bot:
    """One attacker identity: a Chrome-impersonating session with its own cookie jar and address."""

    def __init__(self, actor, rng):
        self.actor, self.ip = actor, bot_ip(rng)
        self.http = cffi.Session(impersonate="chrome150", timeout=30)
        self.requests = 0

    def request(self, method, path, **kw):
        headers = dict(kw.pop("headers", {}) or {}, **lab_headers(self.actor, self.ip))
        self.requests += 1
        return self.http.request(method, BASE_URL + path, headers=headers, **kw)

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, **kw):
        return self.request("POST", path, **kw)

    @property
    def sid(self):
        return self.http.cookies.get("sid")


def verdict(r):
    """outcome() for a response: the gate's words (X-Lab-*) plus whether the body is the data the bot wanted."""
    return outcome(r.status_code, r.headers.get("X-Lab-Verdict"), r.headers.get("X-Lab-Signals"), confirmed=True)


def got_data(r):
    """True when a GraphQL answer carried data (one operation, or a batch)."""
    try:
        body = r.json()
    except ValueError:
        return False
    if isinstance(body, list):
        return bool(body) and all(isinstance(x, dict) and x.get("data") for x in body)
    return isinstance(body, dict) and bool(body.get("data"))


def say(name, result, extra=""):
    mark = {"reserved": "got through", "challenge": "challenged", "blocked": "blocked", "failed": "failed"}.get(result["status"], "?")
    print(f"  {name:<24} {mark:<12} {result.get('http')}  {' '.join(result['signals'])} {extra}")


def emit(name, results, cost, **extra):
    """The last line every attack prints (see _common.finish; this one is for results with their own labels)."""
    out = {"attack": name, "attempted": len(results),
           "succeeded": sum(r["status"] == "reserved" for r in results),
           "blocked": sum(r["status"] in ("blocked", "challenge") for r in results),
           "signals": sorted({s for r in results for s in r["signals"]})[:8],
           "wall_s": round(cost.wall_s, 2), "cpu_s": round(cost.cpu_s, 2)}
    out.update(extra)
    print(json.dumps(out))
    return out
