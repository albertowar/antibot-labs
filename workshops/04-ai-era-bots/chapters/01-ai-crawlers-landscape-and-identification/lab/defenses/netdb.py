"""Reverse and forward DNS against the lab's fixtures (given, not a student exercise).

In production these two functions are DNS:

    socket.gethostbyaddr(ip)[0]          -> PTR name          (reverse DNS)
    socket.gethostbyname_ex(name)[2]     -> list of addresses (forward DNS)

Here they read data/rdns.json, so the lab needs no network and every answer is
deterministic. The shapes and failure modes are the real ones: most addresses have no
PTR record at all, and one address has a PTR that lies (its forward lookup does not
come back to it). Which *network* an address belongs to is not DNS, and not here:
see defenses/netinfo.py (ASN type, derived from the same feeds a production system uses).
"""

from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
RDNS_FILE = os.path.join(os.path.dirname(HERE), "data", "rdns.json")

with open(RDNS_FILE) as _fh:
    _RDNS = json.load(_fh)


def ptr(ip: str) -> str | None:
    """Reverse DNS: the PTR name for ip, or None when there is no PTR record."""
    return _RDNS["ptr"].get(ip)


def forward(name: str) -> list[str]:
    """Forward DNS: the addresses a hostname resolves to (empty when it does not exist)."""
    return list(_RDNS["forward"].get(name, []))
