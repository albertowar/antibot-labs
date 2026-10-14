"""
netinfo: what KIND of network an address belongs to (shared helper, finished).

The store's edge hands every check an ASN, an organization and a country (`ctx.edge`) but never a
network *type*; a production ASN database sells that as a field and you derive it from feeds when
you do not buy one. This module derives it from the files W1 Ch3 builds (`data/feeds/`):

    datacenter   cloud and hosting ranges, hosting ASNs, Tor exits, open proxies
    vpn          commercial VPN ranges (real people, shared addresses)
    relay        privacy-relay ranges (real people: paying Safari customers)
    mobile / corporate / residential   read off the organization name; everything else

The one thing it cannot see is a residential proxy: its exits sit in a real ISP's ranges, so they
read as "residential", exactly as in production. That blind spot is why Round 5's SIVT attacker
beats the GIVT filters.
"""

import bisect
import csv
import ipaddress
import os

FEEDS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "feeds")
_state = {}


def _nets(name):
    with open(os.path.join(FEEDS, name)) as fh:
        return [ipaddress.ip_network(r["cidr"]) for r in csv.DictReader(fh)]


def _load():
    if _state:
        return _state
    ranges = {4: [], 6: []}
    with open(os.path.join(FEEDS, "ip2asn.tsv")) as fh:
        for line in fh:
            if not line.strip():
                continue
            lo, hi, asn, cc, org = line.rstrip("\n").split("\t")
            a, b = ipaddress.ip_address(lo), ipaddress.ip_address(hi)
            ranges[a.version].append((int(a), int(b), int(asn), cc, org))
    for v in ranges:
        ranges[v].sort()
    with open(os.path.join(FEEDS, "hosting_asns.csv")) as fh:
        hosting = {int(r["asn"]) for r in csv.DictReader(fh)}
    listed = set()
    for name in ("tor_exits.txt", "open_proxies.txt"):
        with open(os.path.join(FEEDS, name)) as fh:
            listed |= {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}
    _state.update(ranges=ranges, starts={v: [r[0] for r in rs] for v, rs in ranges.items()}, hosting=hosting,
                  listed=listed, cloud=_nets("cloud_ranges.csv"), vpn=_nets("vpn_ranges.csv"), relay=_nets("relay_ranges.csv"))
    return _state


def lookup(ip):
    """{asn, org, country, asn_type} for an address; asn_type "unknown" when no range covers it."""
    s = _load()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"asn": 0, "org": "", "country": "??", "asn_type": "unknown"}
    rs = s["ranges"][addr.version]
    i = bisect.bisect_right(s["starts"][addr.version], int(addr)) - 1
    if i < 0 or int(addr) > rs[i][1]:
        return {"asn": 0, "org": "", "country": "??", "asn_type": "unknown"}
    _, _, asn, cc, org = rs[i]
    inside = lambda nets: any(addr in n for n in nets if n.version == addr.version)      # noqa: E731
    low = org.lower()
    if inside(s["relay"]):
        kind = "relay"
    elif inside(s["vpn"]):
        kind = "vpn"
    elif asn in s["hosting"] or str(addr) in s["listed"] or inside(s["cloud"]) or any(w in low for w in ("cloud", "hosting", "bulletproof")):
        kind = "datacenter"
    elif "mobile" in low:
        kind = "mobile"
    elif "corp" in low or "university" in low:
        kind = "corporate"
    else:
        kind = "residential"
    return {"asn": asn, "org": org, "country": cc, "asn_type": kind}


if __name__ == "__main__":
    for ip in ["192.0.2.10", "198.51.100.1", "198.51.100.70", "203.0.113.5", "203.0.113.130", "2001:db8:100::1"]:
        print(f"{ip:<18} {lookup(ip)}")
