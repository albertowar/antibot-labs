"""
labclient: how every lab actor (shopper or bot) talks to the store.

Each actor "rents" a source address from a pool in data/world.json and labels
itself for the scoreboard. demo_site/lab_edge.py turns that into the client
address the defenses see and strips the label before they run.

Ethics guardrail: the localhost guard is labnet.py at the lab root (a byte-identical
copy of scripts/labnet.py). On import this module asks it for DEMO_URL, which it
refuses unless it is this machine, and checks every side-service URL that is set
(REDIS_URL, DATABASE_URL, PROVIDER_URL, ...). Lab traffic never leaves localhost,
and no real proxy, VPN or Tor node is ever contacted: the pools are addresses the
store *pretends* to see.

    from labclient import LabClient, world_pool, admin
    bot = LabClient("bot:wave1", ip=world_pool("cloud_vm")[0])
    r = bot.get("/api/products", headers=[("User-Agent", "python-requests/2.34")])
    admin("POST", "/lab/reset")
"""

import ipaddress
import json
import os
import random
import re
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
if LAB not in sys.path:
    sys.path.insert(0, LAB)                    # lab root: labnet.py, demo_site, defenses
from labnet import is_local, require_local, require_local_env, target  # noqa: E402

BASE_URL = target("DEMO_URL", "http://127.0.0.1:5000")
require_local_env()
WORLD_FILE = os.environ.get("WORLD_FILE", os.path.join(LAB, "data", "world.json"))


def assert_local(url=BASE_URL):
    """Refuse a URL that is not this machine (labnet.require_local). Returns the URL."""
    return require_local(url)

with open(WORLD_FILE) as f:
    WORLD = json.load(f)


def world_pool(name, n=None):
    """
    Source addresses in one pool, or in every pool of a `groups` entry (in order): the explicit
    `ips`, or the first `hosts` of the `cidr`, one per /`spread` when the pool sets it.
    Same rule as tools/build_world.py hosts(); tools/smoke.py checks that they agree.
    """
    if name in WORLD.get("groups", {}):
        ips = [ip for member in WORLD["groups"][name] for ip in world_pool(member)]
        return ips[:n] if n else ips
    p = WORLD["pools"][name]
    if "ips" in p:
        ips = list(p["ips"])
    else:
        net = ipaddress.ip_network(p["cidr"])
        count = p.get("hosts", 50)
        if "spread" in p:
            step = 1 << (net.max_prefixlen - p["spread"])
            ips = [str(ipaddress.ip_address(int(net.network_address) + i * step + 1)) for i in range(count)]
        else:
            base = int(net.network_address) + (1 if net.version == 4 and net.prefixlen < 31 else 0)
            ips = [str(ipaddress.ip_address(base + i)) for i in range(count)]
    return ips[:n] if n else ips


def group_members(name):
    """The pool names behind a `groups` entry (or [name] for a plain pool)."""
    return list(WORLD.get("groups", {}).get(name, [name]))


def pool_type(name):
    return WORLD["pools"][name]["type"]


class LabClient:
    """
    A requests.Session that sends headers exactly in the order given (no
    library defaults), from a rented source IP, with a scoreboard label.

    ip      one fixed source IP (a sticky proxy, or a real home connection)
    pool    rotate: pick a random IP from this list on EVERY request (e.g. world_pool("cloud_vm"))
    ja4     a claimed TLS fingerprint (honoured as "claimed" until a TLS edge measures one)
    """

    def __init__(self, actor, ip=None, pool=None, ja4=None, rng=None, timeout=30):
        self.actor, self.ip, self.pool, self.ja4 = actor, ip, pool, ja4
        self.rng = rng or random.Random()
        self.http = requests.Session()
        self.http.headers.clear()            # our order, not requests' defaults
        self.timeout = timeout
        self.requests, self.statuses = 0, []
        self.last = None

    def current_ip(self):
        return self.rng.choice(self.pool) if self.pool else self.ip

    def request(self, method, path, headers=(), data=None, json=None, ip=None, allow_redirects=False):
        lab = [("X-Lab-Client-IP", ip or self.current_ip() or WORLD["student_ip"]), ("X-Lab-Actor", self.actor)]
        if self.ja4:
            lab.append(("X-Lab-JA4", self.ja4))
        hdrs = list(headers) + lab
        r = self.http.request(method, BASE_URL + path, headers=dict(hdrs), data=data, json=json,
                              timeout=self.timeout, allow_redirects=allow_redirects)
        self.requests += 1
        self.statuses.append(r.status_code)
        self.last = r
        return r

    def get(self, path, headers=(), ip=None, **kw):
        return self.request("GET", path, headers, ip=ip, **kw)

    def post(self, path, data=None, headers=(), ip=None, json=None, **kw):
        return self.request("POST", path, headers, data=data, json=json, ip=ip, **kw)

    def set_cookie(self, name, value):
        self.http.cookies.set(name, value, path="/")

    def verdict(self):
        r = self.last
        return (r.headers.get("X-Lab-Verdict"), r.headers.get("X-Lab-Score"), r.headers.get("X-Lab-Signals", "")) if r else None


# --- Reading the store's pages (what a scraper or the JS on the page would see) ---

def form_fields(html):
    """Every <input/select/textarea name=...> and its value, in page order (a naive form filler's view)."""
    fields = {}
    for tag in re.findall(r"<(?:input|select|textarea)[^>]*>", html):
        name = re.search(r'name="([^"]+)"', tag)
        value = re.search(r'value="([^"]*)"', tag)
        if name and (name.group(1) not in fields or "checked" in tag):
            fields[name.group(1)] = value.group(1) if value else ""
    return fields


def csrf_of(html):
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    return m.group(1) if m else ""


def product_skus(html):
    return re.findall(r'class="product-card" data-sku="([^"]+)"', html)


# --- Lab admin -----------------------------------------------------------------

def admin(method, path, **kw):
    """Lab admin calls (reset, level, scoreboard). Not something a real client could do."""
    r = requests.request(method, BASE_URL + path, timeout=60, **kw)
    r.raise_for_status()
    return r.json()


def reset(mode="state", **params):
    return admin("POST", "/lab/reset", params=dict(mode=mode, **params))


def set_level(n):
    return admin("POST", "/lab/level", json={"level": n})


def scoreboard(since=None):
    return admin("GET", "/lab/scoreboard", params={"since": since} if since else None)


def wait_for_store(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            return admin("GET", "/lab/status")
        except requests.RequestException:
            time.sleep(0.5)
    raise SystemExit(f"Store not reachable on {BASE_URL}. Start it: python demo_site/app.py")


# --- Browsers (Playwright), with the same guard --------------------------------

def browser_context(playwright_browser, actor, ip=None, **kw):
    """A Playwright context that carries the lab headers and refuses to leave this machine."""
    ctx = playwright_browser.new_context(extra_http_headers={"X-Lab-Client-IP": ip or WORLD["student_ip"],
                                                             "X-Lab-Actor": actor}, **kw)

    def _route(route):
        if is_local(route.request.url):
            route.continue_()
        else:
            route.abort()
    ctx.route("**/*", _route)
    return ctx
