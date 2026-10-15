"""
The first-party client of the Lab Runner API, shared by the shoppers and the attackers.

What a real app ships, in one place: log in for a bearer token and a signing secret, sign each protected request,
send its GraphQL as the persisted (trusted) documents of data/persisted_queries.json, and open the live drop feed
from its own origin. The attackers use the same plumbing with different habits (no signature, a forged origin, a
fragment instead of a trusted document), which is the point: the defender sees the same wire format either way.

Ethics guardrail: every request goes through tools/labclient.py, which runs the labnet guard (the target must be
this machine) and rents source addresses from data/world.json. The WebSocket client below builds its URL from
labclient.BASE_URL and sends the same X-Lab-* headers, so the feed is no way around the guard either.
"""

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "..")]

from websockets.sync.client import connect  # noqa: E402

import labclient  # noqa: E402  (runs the labnet guard on import)
from defenses import request_signing  # noqa: E402
from labclient import BASE_URL, WORLD, LabClient  # noqa: E402

APP_UA = "LabRunnerApp/4.2 (iOS 18)"
SCRIPT_UA = "python-requests/2.34.2"
DROP_SKU = "lab-runner-9"

with open(os.path.join(HERE, "..", "data", "persisted_queries.json")) as _fh:
    PERSISTED = json.load(_fh)           # name -> the exact document the app ships


class ApiApp:
    """One caller of /api/v2 and /graphql. `ua` and `ip` are whatever the caller claims to be."""

    def __init__(self, actor, ip, ua=APP_UA, timeout=30, client=None):
        self.client = client or LabClient(actor, ip=ip, timeout=timeout)
        self.ua = ua
        self.token = self.secret = None

    def headers(self, extra=()):
        h = [("User-Agent", self.ua), ("Accept", "application/json")]
        if self.token:
            h.append(("Authorization", f"Bearer {self.token}"))
        return h + list(extra)

    def login(self, email, password):
        r = self.client.post("/api/v2/auth/login", json={"email": email, "password": password}, headers=self.headers())
        if r.status_code == 200:
            self.token, self.secret = r.json()["access_token"], r.json()["api_secret"]
        return r

    def get(self, path, signed=False, ip=None):
        extra = []
        if signed and self.secret:
            ts = str(int(time.time()))
            extra = [("X-Timestamp", ts), ("X-Signature", request_signing.sign(self.secret, "GET", path, ts, b""))]
        return self.client.get(path, headers=self.headers(extra), ip=ip)

    def gql(self, query, operation=None, variables=None):
        body = {"query": query}
        if operation:
            body["operationName"] = operation
        if variables:
            body["variables"] = variables
        return self.client.post("/graphql", json=body, headers=self.headers())

    def persisted(self, name, variables=None):
        return self.gql(PERSISTED[name], operation=name, variables=variables)


def ws_url(path="/ws/drop", token=None):
    url = BASE_URL.replace("http://", "ws://", 1) + path
    return f"{url}?token={token}" if token else url


def open_feed(actor, ip, origin=BASE_URL, token=None, ua=APP_UA):
    """Open the live drop feed. Returns a websockets connection (a context manager); raises if refused."""
    headers = {"X-Lab-Client-IP": ip or WORLD["student_ip"], "X-Lab-Actor": actor, "User-Agent": ua}
    if origin:
        headers["Origin"] = origin
    return connect(ws_url(token=token), additional_headers=headers, open_timeout=5, close_timeout=2)


def bid(ws, item=42, amount=1.0):
    """Send one bid frame and wait for the answer. Returns the decoded reply (or None if the server hung up)."""
    try:
        ws.send(json.dumps({"action": "bid", "item_id": item, "amount": amount}))
        return json.loads(ws.recv(timeout=5))
    except Exception:
        return None
