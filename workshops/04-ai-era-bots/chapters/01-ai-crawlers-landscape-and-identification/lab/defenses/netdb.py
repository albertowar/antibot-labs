"""Reverse and forward DNS against the lab's fixtures (given, not a student exercise).

In production these two functions are DNS:

    socket.gethostbyaddr(ip)[0]          -> PTR name          (reverse DNS)
    socket.gethostbyname_ex(name)[2]     -> list of addresses (forward DNS)

Here they read tools/fixtures/dns_zones.json, so the lab needs no network and every
answer is deterministic. That file is the same one Chapter 2's mock internet serves over
HTTP; here it is a local read, so there is no latency, cache or timeout to model.
The shapes and failure modes are the real ones: most addresses have no PTR record at
all, and one address has a PTR that lies (it claims googlebot.com, but no forward record
for that name comes back to it). Which *network* an address belongs to is not DNS, and
not here: see defenses/netinfo.py (ASN type, derived from the same feeds a production
system uses).

The file has explicit `ptr` and `a` records plus `patterns`: whole blocks that get a
generated name (like a hosting provider's default reverse zone). An explicit record wins
over a pattern.
"""

from __future__ import annotations

import ipaddress
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ZONES_FILE = os.path.join(os.path.dirname(HERE), "tools", "fixtures", "dns_zones.json")

with open(ZONES_FILE) as _fh:
    _ZONES = json.load(_fh)

_PATTERNS = [(ipaddress.ip_network(cidr), template)
             for cidr, template in _ZONES.get("patterns", {}).items() if not cidr.startswith("_")]


def ptr(ip: str) -> str | None:
    """Reverse DNS: the PTR name for ip, or None when there is no PTR record."""
    names = _ZONES["ptr"].get(ip)
    if names:
        return names[0]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, template in _PATTERNS:
        if addr in net:
            return template.format(d=ip.replace(".", "-"))
    return None


def forward(name: str) -> list[str]:
    """Forward DNS: the addresses a hostname resolves to (empty when it does not exist)."""
    name = name.lower().rstrip(".")
    if name in _ZONES["a"]:
        return list(_ZONES["a"][name])
    # A generated name resolves back to the address it was made from.
    for net, template in _PATTERNS:
        prefix, suffix = template.split("{d}")
        if name.startswith(prefix) and name.endswith(suffix):
            candidate = name[len(prefix):len(name) - len(suffix)].replace("-", ".")
            try:
                if ipaddress.ip_address(candidate) in net:
                    return [candidate]
            except ValueError:
                pass
    return []
