"""Shared helpers and the ethics guardrail for every attack script.

Rules of engagement are absolute: these scripts run ONLY against the local demo
store you run yourself. ``require_local`` enforces it in code — a non-loopback
target raises before a single request is sent. Lab traffic never touches a third
party, a public proxy, or anyone else's infrastructure. Every credential, email,
IP and session here is synthetic.

The IPs below are RFC 5737 documentation ranges. They are not real hosts; the
store only honours them from loopback, to stand in for the egress a real attacker
would rent. The point of the lab is to train defenders against your own app.
"""

from __future__ import annotations

import os
import sys
import random

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://127.0.0.1:5000")

DATA = os.path.join(os.path.dirname(__file__), "..", "data")

RESIDENTIAL = [f"198.51.100.{i}" for i in range(1, 255)] + [f"203.0.113.{i}" for i in range(1, 255)]
DATACENTER = [f"192.0.2.{i}" for i in range(1, 255)]

REAL_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")


def headers(actor, client_ip, fp="", session="", ua=REAL_UA, referer=""):
    h = {"X-Lab-Actor": actor, "X-Lab-Client-IP": client_ip, "User-Agent": ua}
    if fp:
        h["X-Lab-FP"] = fp
    if session:
        h["X-Lab-Session"] = session
    if referer:
        h["Referer"] = referer
    return h


def rand_ip(pool, rng):
    return rng.choice(pool)
