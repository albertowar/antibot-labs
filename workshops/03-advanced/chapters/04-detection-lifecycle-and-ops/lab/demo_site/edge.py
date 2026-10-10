"""
Chapter 4 (W3): The simulated edge, inherited from W2 Ch8

In production, the first thing a request meets is your edge: a CDN or a
reverse proxy that terminates TLS. The edge knows things the origin cannot
see: the real source IP, its ASN, and the TLS ClientHello (JA4). It passes
them to the origin in headers it sets itself, and strips any client-sent
copies.

On a laptop every request comes from 127.0.0.1 over plain HTTP, so the lab
fakes the edge:
- traffic generators *declare* their source address and TLS stack in
  X-Lab-Client-IP and X-Lab-JA4
- this module resolves the address against ../world.json, as an ASN/geo
  database would, plus whatever ../data/world_updates.json has learned
  since (defenses/corpus.py). The database is a snapshot with a date; the
  internet is not (Round 2).
- it strips every X-Lab-* header so no sensor ever sees them

Lab time: X-Lab-Week and X-Lab-Clock carry the replayer's calendar (five
weeks of traffic in a few minutes). They go to the decision log, the
containment TTL and nowhere else.

X-Lab-Actor (human:<persona> or bot:<script>) is ground truth for the
scoreboard. It is written to the decision log and nowhere else. No defense
may read it: `grep -rn lab_actor ../defenses` must come back empty.

Rules of engagement: attack scripts may only declare addresses from the
world.json pools and JA4s of client stacks they actually imitate.
"""

import ipaddress
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "defenses"))

import corpus  # noqa: E402

with open(os.path.join(HERE, "..", "world.json")) as f:
    WORLD = json.load(f)

POOLS = sorted(((ipaddress.ip_network(p["cidr"]), name, p) for name, p in WORLD["pools"].items()),
              key=lambda t: -t[0].prefixlen)   # most specific prefix first
BLOCKLIST = [ipaddress.ip_network(c) for c in WORLD["community_blocklist"]]


def _describe(ip, name, pool, blocklisted):
    return {"ip": ip, "asn": pool["asn"], "org": pool["org"], "type": pool["type"],
            "country": pool["country"], "tz": pool["tz"], "pool": name, "blocklisted": blocklisted}


def resolve(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "asn": 0, "type": "unknown", "pool": None}
    # What the refresh learned since the snapshot takes precedence (and a
    # refreshed ASN feed also retires the blocklist entries for that range)
    for cidr, name in corpus.updates().get("reassigned", {}).items():
        net = ipaddress.ip_network(cidr)
        if addr.version == net.version and addr in net and name in WORLD["pools"]:
            return _describe(ip, name, WORLD["pools"][name], False)
    for net, name, pool in POOLS:
        if addr.version == net.version and addr in net:
            blocklisted = any(addr in b for b in BLOCKLIST if b.version == addr.version)
            return _describe(ip, name, pool, blocklisted)
    return {"ip": ip, "asn": 0, "type": "unknown", "pool": None}


def from_request(request):
    """Return (edge, ja4, headers_without_lab_headers, lab)."""
    ip = request.headers.get("X-Lab-Client-IP", request.remote_addr)
    ja4 = request.headers.get("X-Lab-JA4", "")
    lab = {"actor": request.headers.get("X-Lab-Actor", "unlabelled"),
           "week": int(request.headers.get("X-Lab-Week", "0") or 0),
           "clock": int(request.headers.get("X-Lab-Clock", "0") or 0)}
    headers = [(k, v) for k, v in request.headers if not k.lower().startswith("x-lab-")]
    return resolve(ip), ja4, headers, lab
