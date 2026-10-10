"""
W1 Ch9 — labnet: how every lab actor (shopper or bot) talks to the store.

Each actor "rents" a source IP from a pool in data/world.json and labels
itself for the scoreboard. demo_site/lab_edge.py turns that into the client
address the defenses see, and strips the label before they run.

Ethics guardrail: this module refuses any DEMO_URL that is not this
machine. Lab traffic never leaves localhost, and no real proxy, VPN or Tor
node is ever contacted: the pools are just addresses the store pretends to
see.

Usage:
    from labnet import LabClient, world_pool
    shop = LabClient("bot:wave1", ip=world_pool("cloud_vm")[0])
    r = shop.get("/drop", headers=[("User-Agent", "...")])
"""

import json
import os
import random
import re
import time
from urllib.parse import urlparse

import requests

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000").rstrip("/")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

if urlparse(BASE_URL).hostname not in LOCAL_HOSTS:
    raise SystemExit(f"Refusing to run against {BASE_URL}: lab traffic only goes to your own machine.")

with open(os.path.join(LAB, "data", "world.json")) as f:
    WORLD = json.load(f)


def world_pool(name):
    """The list of source IPs in one pool of the lab world."""
    return list(WORLD["pools"][name]["ips"])


class LabClient:
    """
    A requests.Session that sends headers exactly in the order given (no
    library defaults), from a rented source IP, with a scoreboard label.

    ip      one fixed source IP (a sticky proxy, or a real home connection)
    pool    rotate: pick a random IP from this pool on EVERY request
    """

    def __init__(self, actor, ip=None, pool=None, rng=None):
        self.actor, self.ip, self.pool = actor, ip, pool
        self.rng = rng or random.Random()
        self.http = requests.Session()
        self.http.headers.clear()            # our order, not requests' defaults
        self.requests = 0
        self.statuses = []

    def current_ip(self):
        return self.rng.choice(self.pool) if self.pool else self.ip

    def request(self, method, path, headers=(), data=None, ip=None):
        lab = [("X-Lab-Source-IP", ip or self.current_ip()), ("X-Lab-Actor", self.actor)]
        response = self.http.request(method, BASE_URL + path, headers=dict(list(headers) + lab),
                                     data=data, timeout=30, allow_redirects=False)
        self.requests += 1
        self.statuses.append(response.status_code)
        return response

    def get(self, path, headers=(), ip=None):
        return self.request("GET", path, headers, ip=ip)

    def post(self, path, data, headers=(), ip=None):
        return self.request("POST", path, headers, data=data, ip=ip)

    def set_cookie(self, name, value):
        self.http.cookies.set(name, value, path="/")


# --- Reading the store's pages (what a scraper or the JS on the page would see) ---

def form_fields(html):
    """Every <input name=...> and its value, in page order (a naive form filler's view)."""
    fields = {}
    for tag in re.findall(r"<(?:input|select)[^>]*>", html):
        name = re.search(r'name="([^"]+)"', tag)
        value = re.search(r'value="([^"]*)"', tag)
        if name:
            fields[name.group(1)] = value.group(1) if value else ""
    return fields


def js_nonce(html):
    """The nonce the page's script reverses into the js_ok cookie (W1 Ch5)."""
    m = re.search(r'"([0-9a-f]{16})"\.split\(""\)', html)
    return m.group(1) if m else None


def pow_bits(html):
    m = re.search(r'data-bits="(\d+)"', html)
    return int(m.group(1)) if m else 0


def admin(method, path):
    """Lab admin calls (reset, scoreboard). Not something a real client could do."""
    r = requests.request(method, BASE_URL + path, timeout=30)
    r.raise_for_status()
    return r.json()


def wait_for_store(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            return admin("GET", "/admin/config")
        except requests.RequestException:
            time.sleep(0.5)
    raise SystemExit(f"Store not reachable on {BASE_URL}. Start it: python demo_site/app.py")
