"""Shared helpers and the ethics guardrail for every attack script.

Rules of engagement for this lab are absolute: attacks run **only** against the
local demo store you are running yourself. ``require_local_target`` enforces it in
code — a non-loopback target raises before a single request is sent. Lab traffic
never touches a third party, a public proxy, or anyone else's infrastructure, and
every credential, IP and session here is synthetic.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://127.0.0.1:5000")
require_local_target = require_local

DATA = os.path.join(os.path.dirname(__file__), "..", "data")


def load_combos() -> list[tuple[str, str]]:
    out = []
    with open(os.path.join(DATA, "combo_list.txt")) as fh:
        for line in fh:
            line = line.strip()
            if ":" in line:
                email, pw = line.split(":", 1)
                out.append((email, pw))
    return out


def load_json(name: str):
    with open(os.path.join(DATA, name)) as fh:
        return json.load(fh)


def edge_headers(actor: str, client_ip: str, device: str = "", client_sig: str = "",
                 user_agent: str = "python-httpx/attack") -> dict:
    """Headers for the simulated network edge: who we claim to be and from where."""
    h = {"X-Lab-Actor": actor, "X-Lab-Client-IP": client_ip, "User-Agent": user_agent}
    if device:
        h["X-Lab-Device"] = device
    if client_sig:
        h["X-Client-Sig"] = client_sig
    return h


def is_success(resp) -> bool:
    try:
        return resp.status_code == 200 and resp.json().get("status") == "success"
    except Exception:
        return False
