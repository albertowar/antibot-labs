"""Network lookups against the lab world (given, not a student exercise).

In production these three functions are DNS and an ASN database:

    socket.gethostbyaddr(ip)[0]          -> PTR name          (reverse DNS)
    socket.gethostbyname_ex(name)[2]     -> list of addresses (forward DNS)
    an ASN feed (iptoasn.com, GeoLite2-ASN; see W1 Ch3 §2.3.6)

Here they read data/world.json, so the lab needs no network and every answer is
deterministic. The shapes and failure modes are the real ones: no PTR for CGNAT
addresses, generic cloud PTRs for operators that publish ranges instead, and one
address whose PTR lies (its forward lookup does not come back to it).
"""

from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
WORLD_FILE = os.path.join(os.path.dirname(HERE), "data", "world.json")

with open(WORLD_FILE) as _fh:
    _WORLD = json.load(_fh)

_IP_INFO: dict[str, dict] = {}
for _name, _pool in _WORLD["pools"].items():
    for _ip in _pool["ips"]:
        _IP_INFO[_ip] = {"pool": _name, "asn": _pool["asn"], "asn_name": _pool["asn_name"],
                         "asn_class": _pool["asn_class"]}

ALL_IPS = frozenset(_IP_INFO)
STUDENT_IP = _WORLD["student_ip"]


def info(ip: str) -> dict:
    """ASN record for an address, or an 'unknown' record for anything off-world."""
    return _IP_INFO.get(ip, {"pool": "unknown", "asn": 0, "asn_name": "unknown", "asn_class": "unknown"})


def asn_class(ip: str) -> str:
    return info(ip)["asn_class"]


def ptr(ip: str) -> str | None:
    """Reverse DNS: the PTR name for ip, or None when there is no PTR record."""
    return _WORLD["ptr"].get(ip)


def forward(name: str) -> list[str]:
    """Forward DNS: the addresses a hostname resolves to (empty when it does not exist)."""
    return list(_WORLD["forward"].get(name, []))
