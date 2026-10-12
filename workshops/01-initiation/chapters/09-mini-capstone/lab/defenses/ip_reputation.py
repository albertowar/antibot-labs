"""
W1 Ch9 — Layer: IP reputation (W1 Ch3, condensed).

Looks the source IP up in offline snapshots of free feeds (data/feeds/,
fetched 2026-10-09; see data/feeds/manifest.json for sources) and scores it
with W1 Ch3's weights, read from policy.IP_POINTS:

    tor_exit, open_proxy, datacenter, known_vpn   40 each
    hosting_asn                                   25
    privacy_relay                                  0 (and, with
                                                     TRUST_PRIVACY_RELAYS, cancels
                                                     the infrastructure signals)

What it catches: rented cloud VMs (wave 1), Tor, listed proxies.
What it misses: residential proxies (waves 2-4). They ARE real home
connections, so their reputation is the same as your customers'.
False positives: corporate VPN users (Zscaler egress on a VPN list) score
40, which is "challenge". Until Round 4 there is no challenge, so the ladder
blocks them. That is the cost Round 2 shows on the scoreboard.

Lookups use sorted range tables and bisect: O(log n) per lookup, and cached.

Run standalone:
    python defenses/ip_reputation.py            # score one IP from each lab pool
    python defenses/ip_reputation.py 3.5.140.10
"""

import bisect
import csv
import ipaddress
import json
import os
import threading
from functools import lru_cache

import policy
from ladder import Signal

FEEDS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "feeds")
INFRASTRUCTURE_SIGNALS = ("datacenter", "hosting_asn", "known_vpn")


class RangeTable:
    """Sorted, possibly overlapping IPv4 ranges with an optional value each."""

    def __init__(self, rows):
        rows = sorted(rows)                      # (first_int, last_int, value)
        self.starts = [r[0] for r in rows]
        self.rows = rows
        self.max_end = []                        # running max of `last`: handles overlaps
        best = -1
        for r in rows:
            best = max(best, r[1])
            self.max_end.append(best)

    def find(self, ip_int):
        """Return the value of a range containing ip_int, or None."""
        k = bisect.bisect_right(self.starts, ip_int) - 1
        if k < 0 or self.max_end[k] < ip_int:
            return None
        while k >= 0:                            # walk back to the covering range
            first, last, value = self.rows[k]
            if first <= ip_int <= last:
                return value if value is not None else True
            if self.max_end[k] < ip_int:
                return None
            k -= 1
        return None


def _net_rows(cidrs, value=None):
    rows = []
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        if net.version == 4:
            first = int(net.network_address)
            rows.append((first, first + net.num_addresses - 1, value))
    return rows


def _lines(name):
    with open(os.path.join(FEEDS_DIR, name)) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


class Reputation:
    def __init__(self):
        self.asn = RangeTable([
            (int(ipaddress.ip_address(first)), int(ipaddress.ip_address(last)), (int(asn), cc, org))
            for first, last, asn, cc, org in (line.split("\t") for line in _lines("ip2asn.tsv"))
        ])
        with open(os.path.join(FEEDS_DIR, "hosting_asns.csv")) as f:
            self.hosting_asns = {int(row["ASN"]) for row in csv.DictReader(f)}
        with open(os.path.join(FEEDS_DIR, "cloud_ranges.csv")) as f:
            self.cloud = RangeTable([row for r in csv.DictReader(f) for row in _net_rows([r["cidr"]], r["provider"])])
        self.tor = set(_lines("tor_exits.txt"))
        self.open_proxies = set(_lines("open_proxies.txt"))
        self.vpn = RangeTable(_net_rows(_lines("vpn_ranges.txt")))
        self.relay = RangeTable([row for line in _lines("private_relay.csv")
                                 for row in _net_rows([line.split(",")[0]], line.split(",")[1])])

    @lru_cache(maxsize=100_000)
    def lookup(self, ip):
        """Network facts about an IP: ASN, organisation, country, cloud provider."""
        addr = ipaddress.ip_address(ip)
        if addr.version != 4 or not addr.is_global:
            return {"asn": None, "org": "internal", "country": None, "provider": None, "relay": None}
        i = int(addr)
        asn, cc, org = self.asn.find(i) or (None, None, None)
        return {"asn": asn, "org": org, "country": cc, "provider": self.cloud.find(i),
                "relay": self.relay.find(i)}

    @lru_cache(maxsize=100_000)
    def signals(self, ip):
        """{signal name: points} for every signal that fires."""
        info = self.lookup(ip)
        if info["org"] == "internal":
            return {}
        i = int(ipaddress.ip_address(ip))
        found = {}
        if ip in self.tor:
            found["tor_exit"] = policy.IP_POINTS["tor_exit"]
        if ip in self.open_proxies:
            found["open_proxy"] = policy.IP_POINTS["open_proxy"]
        if info["provider"]:
            found["datacenter"] = policy.IP_POINTS["datacenter"]
        if info["asn"] in self.hosting_asns:
            found["hosting_asn"] = policy.IP_POINTS["hosting_asn"]
        if self.vpn.find(i):
            found["known_vpn"] = policy.IP_POINTS["known_vpn"]
        if info["relay"]:
            found["privacy_relay"] = policy.IP_POINTS["privacy_relay"]
            if policy.TRUST_PRIVACY_RELAYS:
                for name in INFRASTRUCTURE_SIGNALS:
                    found.pop(name, None)
        return found


_reputation = None
_loading = threading.Lock()


def reputation():
    """The shared tables, loaded once (the store calls this at startup)."""
    global _reputation
    with _loading:
        if _reputation is None:
            _reputation = Reputation()
    return _reputation


def lookup(ip):
    return reputation().lookup(ip)


def check(ctx):
    """Layer entry point."""
    net = ctx.network
    where = f"AS{net['asn']} {net['org']}" if net.get("asn") else "unknown network"
    return [Signal("ip_reputation", name, points, where)
            for name, points in reputation().signals(ctx.ip).items()]


if __name__ == '__main__':
    import sys
    rep = reputation()
    if len(sys.argv) > 1:
        ips = [("", ip) for ip in sys.argv[1:]]
    else:
        with open(os.path.join(FEEDS_DIR, "..", "world.json")) as f:
            pools = json.load(f)["pools"]
        ips = [(name, pool["ips"][0]) for name, pool in pools.items()]
    for pool, ip in ips:
        sig = rep.signals(ip)
        info = rep.lookup(ip)
        print(f"{pool:<18} {ip:<16} AS{info['asn']} {str(info['org'])[:28]:<28} "
              f"score={min(100, sum(sig.values())):>3}  {sig}")
