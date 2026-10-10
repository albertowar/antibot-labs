"""
Chapter 8: The simulated edge

In production, the first thing a request meets is your edge: a CDN or a
reverse proxy that terminates TLS. The edge knows things the origin cannot
see: the real source IP, its ASN, and the TLS ClientHello (JA4). It
passes them to the origin in headers it sets itself, and strips any
client-sent copies.

On a laptop every request comes from 127.0.0.1 over plain HTTP, so the lab
fakes the edge:
- traffic generators *declare* their source address and TLS stack in
  X-Lab-Client-IP and X-Lab-JA4
- this module resolves the address against ../world.json, as an ASN/geo
  database would
- it strips every X-Lab-* header so no sensor ever sees them

Rules of engagement: attack scripts may only declare addresses from the
world.json pools and JA4s of client stacks they actually imitate. That
matches what a real attacker can buy: a datacenter address or a residential
proxy, but never your own customers' IPs at will.

X-Lab-Actor (human:<persona> or bot:<script>) is ground truth for the
scoreboard. It is written to the decision log and nowhere else. No defense
may read it: `grep -rn lab_actor ../defenses` must come back empty.
"""

import ipaddress
import json
import os

with open(os.path.join(os.path.dirname(__file__), "..", "world.json")) as f:
    WORLD = json.load(f)

POOLS = [(ipaddress.ip_network(p["cidr"]), name, p) for name, p in WORLD["pools"].items()]
BLOCKLIST = [ipaddress.ip_network(c) for c in WORLD["community_blocklist"]]


def resolve(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "asn": 0, "type": "unknown", "pool": None}
    for net, name, pool in POOLS:
        if addr.version == net.version and addr in net:
            return {"ip": ip, "asn": pool["asn"], "org": pool["org"], "type": pool["type"],
                    "country": pool["country"], "tz": pool["tz"], "pool": name,
                    "blocklisted": any(addr in b for b in BLOCKLIST if b.version == addr.version)}
    return {"ip": ip, "asn": 0, "type": "unknown", "pool": None}


def from_request(request):
    """Return (edge, ja4, headers_without_lab_headers, lab_actor)."""
    ip = request.headers.get("X-Lab-Client-IP", request.remote_addr)
    ja4 = request.headers.get("X-Lab-JA4", "")
    lab_actor = request.headers.get("X-Lab-Actor", "unlabelled")
    headers = [(k, v) for k, v in request.headers if not k.lower().startswith("x-lab-")]
    return resolve(ip), ja4, headers, lab_actor
