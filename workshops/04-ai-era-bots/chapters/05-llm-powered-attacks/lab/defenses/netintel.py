"""
Network intelligence helper: is this egress a datacenter or a home connection?

Not a check and not student-edited. Round 2's policy and the attack scripts' reports use it. The store
exposes no pool type on `ctx.edge` (the simulated edge keeps the world's labels to itself), so, like
production, it infers the class of an address from the feeds in `data/feeds/` (W1 Ch3): the published
cloud ranges and the hosting ASNs. Everything else is "residential", which is the honest default and
also the gap: a residential proxy (what Round 3's extractor rents) looks exactly like a person.
"""

import csv
import ipaddress
import os

FEEDS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "feeds")
_cache = {}


def _load():
    if not _cache:
        with open(os.path.join(FEEDS, "cloud_ranges.csv"), newline="") as f:
            _cache["ranges"] = [ipaddress.ip_network(r["cidr"]) for r in csv.DictReader(f)]
        with open(os.path.join(FEEDS, "hosting_asns.csv"), newline="") as f:
            _cache["asns"] = {int(r["asn"]) for r in csv.DictReader(f)}
    return _cache


def net_type(ip, asn=0):
    """'datacenter' for a published cloud range or a hosting ASN, else 'residential'."""
    feeds = _load()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if asn in feeds["asns"] or any(addr in net for net in feeds["ranges"] if net.version == addr.version):
        return "datacenter"
    return "residential"
