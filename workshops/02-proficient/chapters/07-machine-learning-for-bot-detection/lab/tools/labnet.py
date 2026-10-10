"""
Chapter 7 — Lab network: the localhost guard, the simulated edge and lab time

Every simulated client (real users and bots alike) goes through this module.

1. Localhost only. `target()` refuses any DEMO_URL that is not this
   machine. Lab traffic never leaves your laptop, and never goes through
   public proxies or anyone else's infrastructure.

2. Simulated network. Real residential proxies, CGNAT carriers and VPNs
   are replaced by `Pool`, which hands out addresses from the private
   prefixes in defenses/netinfo.py. The client sends its address in
   `X-Lab-Client-IP`, standing in for what your CDN would tell the app.
   Pools carry a *simulated* price per GB, so attacks report what they
   would cost, the attacker-side metric that matters most.

3. Lab time. LAB_TIME_SCALE (default 0.02) compresses think time: a 10 s
   pause is slept as 0.2 s. The server divides every measured gap by the
   same factor, so features come out in "real" seconds.
"""

import os
import random
import sys
import time
from urllib.parse import urlparse

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "defenses"))

from store import LAB_TIME_SCALE  # noqa: E402

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Simulated page weight for the attacker's bandwidth bill
PAGE_WITH_ASSETS_KB = 1800
PAGE_ONLY_KB = 60
API_KB = 4


def target():
    """Base URL of the demo site. Refuses anything that is not this machine."""
    url = os.environ.get("DEMO_URL", "http://localhost:5000").rstrip("/")
    host = urlparse(url).hostname
    if host not in LOCAL_HOSTS:
        sys.exit(f"Refusing to run against {url}: lab traffic must stay on localhost.")
    return url


def think(virtual_seconds):
    """Sleep a virtual duration, compressed by LAB_TIME_SCALE."""
    time.sleep(max(virtual_seconds, 0) * LAB_TIME_SCALE)


class Pool:
    """
    A simulated address pool.

      residential  rotating exits on home ISPs. ~$4/GB, the 2025–26 street price range
                   for residential proxy bandwidth is roughly $1–8/GB.
      datacenter   cloud servers. Nearly free, and easy to spot by ASN.
      mobile       CGNAT carrier: few IPs, many users. Used by real phones here.
      vpn          commercial VPN exits (hosting ASN, NL).
      corporate    office egress: one /24 for a whole company.
    """

    SPECS = {
        # kind: (list of (prefix a.b, country), third-octet range, host range, $/GB)
        "residential": ([("10.1", "ES"), ("10.2", "US"), ("10.3", "DE"),
                         ("10.4", "GB"), ("10.5", "US")], (0, 255), (2, 254), 4.0),
        "datacenter": ([("172.16", "US"), ("172.17", "DE")], (0, 15), (2, 254), 0.10),
        "mobile": ([("100.64", "ES"), ("100.65", "US"), ("100.66", "DE")], (0, 1), (2, 12), 0.0),
        "vpn": ([("172.20", "NL")], (0, 3), (2, 254), 0.0),
        "corporate": ([("192.168", "US")], (1, 1), (2, 40), 0.0),
    }

    def __init__(self, kind, country=None, rng=None):
        self.kind = kind
        prefixes, self.octet3, self.host, self.usd_per_gb = self.SPECS[kind]
        if country:
            prefixes = [p for p in prefixes if p[1] == country] or prefixes
        self.prefixes = prefixes
        self.rng = rng or random.Random()

    def next(self):
        """Return (ip, country) for the next session."""
        ab, cc = self.rng.choice(self.prefixes)
        return f"{ab}.{self.rng.randint(*self.octet3)}.{self.rng.randint(*self.host)}", cc


class Client:
    """One browser-ish session: cookie jar, fixed source IP, bandwidth meter."""

    def __init__(self, ip, user_agent, extra_headers=None):
        # Connection: close sidesteps keep-alive races in Flask's development server
        headers = {"User-Agent": user_agent, "X-Lab-Client-IP": ip, "Connection": "close"}
        headers.update(extra_headers or {})
        self.http = httpx.Client(base_url=target(), headers=headers, timeout=30,
                                 transport=httpx.HTTPTransport(retries=3))
        self.ip = ip
        self.kb = 0
        self.last_url = None

    def get(self, path, page=False, assets=False, **kw):
        headers = kw.pop("headers", {})
        if page and self.last_url and "Referer" not in headers:
            headers["Referer"] = self.last_url
        r = self.http.get(path, headers=headers, **kw)
        if page:
            self.last_url = f"{target()}{path}"
            self.kb += PAGE_WITH_ASSETS_KB if assets else PAGE_ONLY_KB
        else:
            self.kb += API_KB
        return r

    def post(self, path, json=None):
        self.kb += API_KB
        return self.http.post(path, json=json)

    @property
    def sid(self):
        return self.http.cookies.get("sid")

    def close(self):
        self.http.close()
