"""Shared helpers and the ethics guardrail for every attack script.

Rules of engagement for this lab are absolute: attacks run **only** against the
local demo store you are running yourself. ``require_local_target`` enforces it in
code — a non-loopback target raises before a single request is sent. Lab traffic
never touches a third party, a public proxy, or anyone else's infrastructure, and
every credential, IP and session here is synthetic.
"""

from __future__ import annotations

import ipaddress
import json
import os
from urllib.parse import urlparse

BASE_URL = os.environ.get("DEMO_URL", "http://127.0.0.1:5000")
DATA = os.path.join(os.path.dirname(__file__), "..", "data")


def require_local_target(url: str) -> str:
    """Refuse any target that is not loopback. This is a safety control, not a check
    you should remove to 'test against something real' — don't."""
    host = urlparse(url).hostname or ""
    if host in {"localhost"}:
        return url
    try:
        if ipaddress.ip_address(host).is_loopback:
            return url
    except ValueError:
        pass
    raise SystemExit(
        f"Refusing to run against non-local target {host!r}. "
        f"This lab only ever targets the local demo store (127.0.0.1)."
    )


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
