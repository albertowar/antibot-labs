"""
promokit: helpers every Chapter 8 attack shares.

The target is the promo voucher at /promo/. An attack unlocks the quiz once, then tries to
turn that single unlock into many vouchers. What changes between rounds is HOW: replaying the
signed cookie, resetting the session, skipping the page, or minting sessions in a browser.

Every address and every "browser" here is synthetic: labclient (and labnet.py behind it)
refuses any DEMO_URL that is not this machine, and the IP pools are addresses the store only
pretends to see. Nothing leaves localhost.
"""

import base64
import collections
import json
import re

import browsers
from labclient import BASE_URL, LabClient

CHROME = ("chrome", 153, "windows")
JSON_HEADERS = [("Accept", "application/json")]
NONCE_RE = re.compile(r'var n = "([0-9a-f]+)"')


def browser_headers(kind="typed", referer=None):
    return browsers.headers_for(CHROME, kind, BASE_URL, referer)


def new_client(name, ip=None, pool=None):
    return LabClient(name, ip=ip, pool=pool)


def unlock(client):
    """Answer the quiz (a form POST, as the page sends it). Returns the response."""
    return client.post("/promo/unlock", data={"answer": "7"},
                       headers=browser_headers("post", BASE_URL + "/promo/"))


def redeem(client):
    """Claim a voucher. The body is empty; what matters is the cookies and identity headers."""
    return client.post("/promo/redeem", data={},
                       headers=browser_headers("post", BASE_URL + "/promo/") + JSON_HEADERS)


def land_and_unlock(client):
    """Walk the human path once: land, open the promo, answer the quiz. Returns the response."""
    client.get("/", browser_headers("typed"))
    client.get("/promo/", browser_headers("link", BASE_URL + "/"))
    return unlock(client)


def decode_cookie(value):
    """Read an itsdangerous payload WITHOUT the key: it is signed, not encrypted."""
    if not value:
        return None
    payload = value.split(".")[0]
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    return json.loads(raw)


def tally(client, counter):
    # Read the signals off the last response directly, so blocked (4xx) responses count too.
    r = client.last
    sigs = r.headers.get("X-Lab-Signals", "") if r is not None else ""
    for flag in filter(None, sigs.split(",")):
        counter[flag] += 1


def report(name, attempted, succeeded, signals=None, **extra):
    out = {"name": name, "attempted": attempted, "succeeded": succeeded,
           "signals": dict(signals or {})}
    out.update(extra)
    print(json.dumps(out, default=str))
    return out
