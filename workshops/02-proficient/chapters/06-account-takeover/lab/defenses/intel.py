"""Network-edge lookups for the lab (shared helper, not a student exercise).

Maps a (simulated) client IP to the signals a real edge would attach: the ASN,
a coarse network type, and a /24 cohort key. In production these come from an IP
intelligence feed (W1 Ch2) and your CDN; here they come from a small synthetic
table over documentation and benchmark ranges only (RFC 5737, RFC 6598 CGNAT,
RFC 2544 benchmark, RFC 5398 documentation ASNs). No real address space is used.
"""

from __future__ import annotations

import csv
import ipaddress
import os
from functools import lru_cache

_DATA = os.path.join(os.path.dirname(__file__), "..", "data", "ip_intel.csv")


@lru_cache(maxsize=1)
def _table():
    rows = []
    with open(_DATA, newline="") as fh:
        for row in csv.DictReader(fh):
            rows.append((ipaddress.ip_network(row["cidr"]), row["asn"], row["type"]))
    # Most specific prefix first so overlapping ranges resolve deterministically.
    rows.sort(key=lambda r: r[0].prefixlen, reverse=True)
    return rows


def cohort_of(ip: str) -> str:
    """Coarse grouping key: the /24 the address falls in.

    A /24 is the smallest block most networks route and reassign, so it is the
    natural unit for "treat these addresses as one source" without punishing a
    whole ASN. Stuffers that rotate inside one rented block collapse to one key.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.version == 4:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
    return str(ipaddress.ip_network(f"{ip}/48", strict=False).network_address)


def lookup(ip: str) -> dict:
    """Return {asn, type, cohort} for a client IP."""
    cohort = cohort_of(ip)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"asn": "", "type": "unknown", "cohort": cohort}
    for net, asn, netype in _table():
        if addr in net:
            return {"asn": asn, "type": netype, "cohort": cohort}
    return {"asn": "", "type": "unknown", "cohort": cohort}
