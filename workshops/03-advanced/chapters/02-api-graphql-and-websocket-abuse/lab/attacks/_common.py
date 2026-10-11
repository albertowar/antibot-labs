"""Shared helpers and the ethics guardrail for every attack script.

Rules of engagement for this lab are absolute: attacks run **only** against the
local demo store you run yourself. ``require_local_target`` enforces it in code —
a non-loopback target raises before a single request is sent. Lab traffic never
touches a third party, a public proxy, or anyone else's infrastructure, and every
account, product, token and egress IP here is synthetic. The "egress" IP is a
header the local app honours only from loopback, drawn from the documentation
ranges in RFC 5737 (192.0.2.0/24 is the attacker's datacenter), so no real
address is ever used.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://127.0.0.1:5000")
require_local_target = require_local

# Egress IPs the demo app recognises (RFC 5737). Attackers come from a datacenter
# range; the legitimate simulator claims residential ranges.
DATACENTER_IP = "192.0.2.66"
SCRIPT_UA = "python-httpx/attack"


def headers(actor: str, egress_ip: str = DATACENTER_IP, ua: str = SCRIPT_UA,
            extra: dict | None = None) -> dict:
    h = {"X-Lab-Actor": actor, "X-Lab-Egress": egress_ip, "User-Agent": ua}
    if extra:
        h.update(extra)
    return h


def ws_url(path: str = "/ws/drop", token: str = "") -> str:
    base = BASE_URL.replace("http://", "ws://").replace("https://", "wss://")
    url = base + path
    if token:
        url += f"?token={token}"
    return url
