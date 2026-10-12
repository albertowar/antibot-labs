"""
The IP intelligence feeds in data/feeds/, loaded into structures you can query per request.

    CidrIndex   a set of CIDR ranges (IPv4 and IPv6) with O(log n) membership tests
    RangeTable  start-end ranges with a value each (ip2asn: range -> ASN, country, org)
    feeds()     every file in data/feeds/, parsed once and reloaded when a file changes

The feeds are synthetic (see data/feeds/README.md): built from data/world.json by
tools/build_world.py, shaped like Spamhaus DROP, FireHOL, the Tor exit list, cloud range
files, iptoasn and the community VPN and hosting lists. Production fetches the real
ones on a schedule; this lab never downloads anything.

Why an index: `any(addr in net for net in networks)` is a linear scan. At a few
thousand ranges that is about a millisecond per request in Python, on every request.
collapse_addresses() merges overlapping and adjacent ranges, so the result is sorted
and disjoint, and bisect finds the one range that could hold an address.

    python -m defenses.feeds            # linear scan vs CidrIndex on a synthetic 5,000-range list
"""

import bisect
import csv
import ipaddress
import json
import os
import threading
import time

FEEDS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "feeds")


class CidrIndex:
    """A set of CIDR ranges with O(log n) membership tests."""

    def __init__(self, networks=()):
        by_version = {4: [], 6: []}
        for n in networks:
            net = ipaddress.ip_network(n, strict=False)
            by_version[net.version].append(net)
        self._starts, self._ends = {4: [], 6: []}, {4: [], 6: []}
        for version, nets in by_version.items():
            # collapse_addresses merges overlaps and neighbours, so the result is sorted and disjoint
            for net in ipaddress.collapse_addresses(nets):
                self._starts[version].append(int(net.network_address))
                self._ends[version].append(int(net.broadcast_address))

    def __contains__(self, ip):
        addr = ipaddress.ip_address(ip)
        starts = self._starts[addr.version]
        i = bisect.bisect_right(starts, int(addr)) - 1
        return i >= 0 and int(addr) <= self._ends[addr.version][i]

    def __len__(self):
        return len(self._starts[4]) + len(self._starts[6])


class RangeTable:
    """Disjoint (first, last, value) address ranges; find() returns the value of the range holding an IP."""

    def __init__(self, rows):
        self._rows = {4: [], 6: []}
        for first, last, value in rows:
            a, b = ipaddress.ip_address(first), ipaddress.ip_address(last)
            self._rows[a.version].append((int(a), int(b), value))
        for v in self._rows:
            self._rows[v].sort(key=lambda r: r[0])
        self._starts = {v: [r[0] for r in rows] for v, rows in self._rows.items()}

    def find(self, ip):
        addr = ipaddress.ip_address(ip)
        i = bisect.bisect_right(self._starts[addr.version], int(addr)) - 1
        if i < 0:
            return None
        first, last, value = self._rows[addr.version][i]
        return value if first <= int(addr) <= last else None


def _lines(name):
    with open(os.path.join(FEEDS_DIR, name)) as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def _csv(name):
    with open(os.path.join(FEEDS_DIR, name)) as f:
        return list(csv.DictReader(f))


class Feeds:
    """Everything in data/feeds/, parsed. Built by feeds(); do not construct per request."""

    def __init__(self):
        self.asn = RangeTable((first, last, (int(asn), cc, org))
                              for first, last, asn, cc, org in (ln.split("\t") for ln in _lines("ip2asn.tsv")))
        self.cloud = CidrIndex(r["cidr"] for r in _csv("cloud_ranges.csv"))
        self.cloud_provider = RangeTable((str(n.network_address), str(n.broadcast_address), r["provider"])
                                         for r in _csv("cloud_ranges.csv") for n in [ipaddress.ip_network(r["cidr"])])
        self.hosting_asns = {int(r["asn"]) for r in _csv("hosting_asns.csv")}
        self.vpn = CidrIndex(r["cidr"] for r in _csv("vpn_ranges.csv"))
        self.relay = CidrIndex(r["cidr"] for r in _csv("relay_ranges.csv"))
        self.tor = set(_lines("tor_exits.txt"))
        self.open_proxies = set(_lines("open_proxies.txt"))
        self.drop = CidrIndex(json.loads(ln)["cidr"] for ln in _lines("drop_v4.json"))
        self.firehol = CidrIndex(_lines("firehol_level1.netset"))


_cache = {"mtimes": None, "feeds": None, "checked": 0.0}
_lock = threading.Lock()
RECHECK_S = 1.0         # look at the files at most once a second, not on every lookup


def _mtimes():
    return tuple(sorted((n, os.stat(os.path.join(FEEDS_DIR, n)).st_mtime) for n in os.listdir(FEEDS_DIR)))


def feeds():
    """The parsed feeds, reloaded when any file in data/feeds/ changes (rebuild with tools/build_world.py)."""
    now = time.monotonic()
    if _cache["feeds"] is not None and now - _cache["checked"] < RECHECK_S:
        return _cache["feeds"]
    with _lock:
        m = _mtimes()
        if _cache["mtimes"] != m:
            _cache["feeds"], _cache["mtimes"] = Feeds(), m
        _cache["checked"] = now
        return _cache["feeds"]


def _bench():
    import random
    rng = random.Random(1337)
    # A list the size of FireHOL level 1, inside the IPv4 test ranges and private space only.
    nets = [ipaddress.ip_network(f"10.{rng.randrange(256)}.{rng.randrange(256)}.0/{rng.choice([24, 26, 28])}", strict=False)
            for _ in range(5000)]
    probes = [f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}" for _ in range(200)]
    idx = CidrIndex(nets)
    t0 = time.perf_counter()
    slow = [any(ipaddress.ip_address(p) in n for n in nets) for p in probes]
    t1 = time.perf_counter()
    fast = [p in idx for p in probes]
    t2 = time.perf_counter()
    assert slow == fast
    print(f"Loaded {len(nets)} CIDR ranges ({len(idx)} after merging)")
    print(f"  200 lookups: linear scan {(t1 - t0) * 1000:.0f} ms, CidrIndex {(t2 - t1) * 1000:.1f} ms")
    f = feeds()
    print(f"data/feeds: {len(f.tor)} Tor exits, {len(f.open_proxies)} open proxies, {len(f.firehol)} FireHOL ranges, "
          f"{len(f.hosting_asns)} hosting ASNs")


if __name__ == "__main__":
    _bench()
