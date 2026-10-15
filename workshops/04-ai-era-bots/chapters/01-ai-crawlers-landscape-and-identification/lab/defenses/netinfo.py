"""
netinfo: what the model may know about the network a session came from.

The store's edge hands every check an ASN, an organization and a country (`ctx.edge`).
It never says what KIND of network that is: a production ASN database (IPinfo, MaxMind
GeoIP2) sells that as a separate "type" field, and you derive it yourself from feeds
when you do not buy one. So does this module, from the same files W1 Ch3 uses
(`data/feeds/`): hosting ASNs, cloud and VPN ranges, Tor exits and open proxies mean
"datacenter"; the rest is read off the organization name.

    asn_type  one of ASN_TYPES. The strongest single feature for a bot model, and the
              one that hurts VPN users, cloud desktops and corporate egress the most.
              Treat it as context, never a verdict.

The one thing this module cannot see is a residential proxy: its exits sit in a real
ISP's ranges, so they are "residential" here, exactly as in production. That blind spot
is the point of Round 1.
"""

import bisect
import csv
import ipaddress
import os

FEEDS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "feeds")
ASN_TYPES = ["residential", "mobile", "datacenter", "corporate", "unknown"]

_DC_WORDS = ("cloud", "hosting", "vps", "vpn", "tor ", "bulletproof", "datacenter")
_state = {}


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
    nets = []
    for name in ("cloud_ranges.csv", "vpn_ranges.csv"):
        with open(os.path.join(FEEDS, name)) as fh:
            nets += [ipaddress.ip_network(r["cidr"]) for r in csv.DictReader(fh)]
    with open(os.path.join(FEEDS, "hosting_asns.csv")) as fh:
        hosting = {int(r["asn"]) for r in csv.DictReader(fh)}
    listed = set()
    for name in ("tor_exits.txt", "open_proxies.txt"):
        with open(os.path.join(FEEDS, name)) as fh:
            listed |= {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}
    _state.update(ranges=ranges, starts={v: [r[0] for r in rs] for v, rs in ranges.items()},
                  nets=nets, hosting=hosting, listed=listed)
    return _state


def lookup(ip):
    """{asn, org, country, asn_type} for an address; 'unknown' when no range covers it."""
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
    low = org.lower()
    if (asn in s["hosting"] or str(addr) in s["listed"] or any(addr in n for n in s["nets"] if n.version == addr.version)
            or any(w in low for w in _DC_WORDS)):
        kind = "datacenter"
    elif "mobile" in low:
        kind = "mobile"
    elif "corp" in low or "university" in low:
        kind = "corporate"
    else:
        kind = "residential"
    return {"asn": asn, "org": org, "country": cc, "asn_type": kind}


if __name__ == "__main__":
    for ip in ["192.0.2.10", "198.51.100.1", "203.0.113.5", "203.0.113.130", "198.51.100.20", "2001:db8:100::1", "8.8.8.8"]:
        print(f"{ip:<18} {lookup(ip)}")
