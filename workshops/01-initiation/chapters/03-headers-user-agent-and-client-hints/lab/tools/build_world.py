"""
Build the published feeds a production stack would buy or download, from data/world.json:

    data/feeds/ip2asn.tsv              range_start  range_end  asn  country  org     (every pool)
    data/feeds/cloud_ranges.csv        cidr,provider                                 (type datacenter)
    data/feeds/hosting_asns.csv        asn,org                                       (type datacenter, proxy)
    data/feeds/vpn_ranges.csv          cidr,provider                                 (type vpn)
    data/feeds/relay_ranges.csv        cidr,provider                                 (type relay)
    data/feeds/tor_exits.txt           one address per line                          (type tor)
    data/feeds/open_proxies.txt        one address per line                          (type proxy)
    data/feeds/drop_v4.json            one JSON object per line, like Spamhaus DROP  (type blocklisted)
    data/feeds/firehol_level1.netset   one CIDR per line, like FireHOL level 1       (community_blocklist + DROP)
    data/feeds/manifest.json           provenance of every file above
    data/feeds/README.md               the same, for people

Defenses read THESE, never world.json's `type`: that is the W1 Ch2 lesson. A
pool that is "residential_proxy" shows up in ip2asn as a residential ISP,
exactly as a real residential proxy does.

Every feed is synthetic. Free real feeds have gaps, and a pool can carry them:

    "feeds": {"hosting_asns": false}   a cloud whose ASN no community hosting list carries
    "feeds": {"vpn_ranges": true}      a privacy relay that community VPN lists include anyway
    "listed": 0.75                     only the first 75% of the hosts are on the per-address
                                       feed (tor_exits, open_proxies); the rest are "fresher
                                       than your copy". CIDR feeds list the whole pool.
    "spread": 64                       one host per /64 instead of consecutive addresses

    python tools/build_world.py          # (re)write the feeds
    python tools/build_world.py --check  # exit 1 if the feeds are stale or world.json breaks the rules
"""

import ipaddress
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
FEEDS = os.path.join(LAB, "data", "feeds")

# When the shapes below were last compared with the real feeds. Bump it by hand after a review;
# a timestamp would make --check fail on every run.
SHAPE_REVIEWED = "2026-10"

FEED_DEFAULTS = {
    "datacenter": {"cloud_ranges", "hosting_asns"},
    "proxy": {"hosting_asns", "open_proxies"},
    "vpn": {"vpn_ranges"},
    "relay": {"relay_ranges"},
    "tor": {"tor_exits"},
    "blocklisted": {"drop"},
}
PER_ADDRESS = {"tor_exits", "open_proxies"}
POOL_FEEDS = {"cloud_ranges", "hosting_asns", "vpn_ranges", "relay_ranges", "tor_exits", "open_proxies", "drop"}

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
DOC_ASNS = list(range(64496, 64512)) + list(range(65536, 65552))

# What each synthetic file stands in for. Licences as listed in the W1 Ch2 tools table.
SOURCES = {
    "ip2asn.tsv": ("iptoasn.com ip2asn-combined", "https://iptoasn.com/", "PDDL", "daily"),
    "cloud_ranges.csv": ("AWS, Google Cloud, DigitalOcean, Cloudflare published ranges",
                         "https://ip-ranges.amazonaws.com/ip-ranges.json (and peers)", "Public", "daily"),
    "hosting_asns.csv": ("brianhama/bad-asn-list", "https://github.com/brianhama/bad-asn-list", "See repository", "weekly"),
    "vpn_ranges.csv": ("X4BNet/lists_vpn", "https://github.com/X4BNet/lists_vpn", "See repository", "daily"),
    "relay_ranges.csv": ("Apple iCloud Private Relay egress ranges", "https://mask-api.icloud.com/egress-ip-ranges.csv",
                         "Public", "daily"),
    "tor_exits.txt": ("Tor Project bulk exit list", "https://check.torproject.org/torbulkexitlist", "Public", "30 min"),
    "open_proxies.txt": ("TheSpeedX/PROXY-List (discussed in W1 Ch2; never fetched by any lab)",
                         "https://github.com/TheSpeedX/PROXY-List", "See repository", "hourly"),
    "drop_v4.json": ("Spamhaus DROP", "https://www.spamhaus.org/drop/drop_v4.json", "Free for non-commercial use", "daily"),
    "firehol_level1.netset": ("FireHOL level 1 (without its bogon entries)",
                              "https://iplists.firehol.org/?ipset=firehol_level1", "Per-list (see repository)", "daily"),
}


def hosts(p):
    """The source addresses of a pool: explicit `ips`, or `hosts` addresses from the `cidr` (one per /`spread`)."""
    if "ips" in p:
        return list(p["ips"])
    net = ipaddress.ip_network(p["cidr"])
    base = int(net.network_address)
    if "spread" in p:
        step = 1 << (net.max_prefixlen - p["spread"])
        return [str(ipaddress.ip_address(base + i * step + 1)) for i in range(p.get("hosts", 50))]
    base += 1 if net.version == 4 and net.prefixlen < 31 else 0
    return [str(ipaddress.ip_address(base + i)) for i in range(p.get("hosts", 50))]


def feeds_of(p):
    out = set(FEED_DEFAULTS.get(p["type"], ()))
    for name, on in p.get("feeds", {}).items():
        (out.add if on else out.discard)(name)
    return out


def validate(world):
    """Documentation addresses and ASNs only, no overlapping pools, known feed flags."""
    problems, nets = [], []
    for name, p in world["pools"].items():
        cidrs = [p["cidr"]] if "cidr" in p else p.get("ips", [])
        for c in cidrs:
            net = ipaddress.ip_network(c)
            if not any(net.version == d.version and net.subnet_of(d) for d in DOC_NETS):
                problems.append(f"{name}: {c} is not a documentation range (RFC 5737 / RFC 3849)")
            nets.append((net, name))
        if p["asn"] not in DOC_ASNS:
            problems.append(f"{name}: AS{p['asn']} is not a documentation ASN (RFC 5398)")
        if not set(p.get("feeds", {})) <= POOL_FEEDS:
            problems.append(f"{name}: unknown feed in {sorted(p['feeds'])}")
        if not 0 <= p.get("listed", 1) <= 1:
            problems.append(f"{name}: listed must be between 0 and 1")
        if "spread" in p and ("cidr" not in p or p["spread"] < ipaddress.ip_network(p["cidr"]).prefixlen):
            problems.append(f"{name}: spread needs a cidr no longer than /{p['spread']}")
    for i, (a, an) in enumerate(nets):
        for b, bn in nets[i + 1:]:
            if an != bn and a.version == b.version and a.overlaps(b):
                problems.append(f"{an} and {bn} overlap ({a}, {b})")
    for g, members in world.get("groups", {}).items():
        problems += [f"group {g}: no pool {m}" for m in members if m not in world["pools"]]
    return problems


def build(world):
    out = {"ip2asn.tsv": [], "cloud_ranges.csv": ["cidr,provider"], "hosting_asns.csv": ["asn,org"],
           "vpn_ranges.csv": ["cidr,provider"], "relay_ranges.csv": ["cidr,provider"], "tor_exits.txt": [], "open_proxies.txt": [],
           "drop_v4.json": [], "firehol_level1.netset": list(world.get("community_blocklist", []))}
    seen_asn = set()
    for name, p in world["pools"].items():
        net = ipaddress.ip_network(p["cidr"]) if "cidr" in p else None
        start, end = (str(net.network_address), str(net.broadcast_address)) if net else (p["ips"][0], p["ips"][-1])
        out["ip2asn.tsv"].append(f"{start}\t{end}\t{p['asn']}\t{p['country']}\t{p['org']}")
        f = feeds_of(p)
        hs = hosts(p)
        listed = hs[:math.ceil(len(hs) * p.get("listed", 1))]
        if "cloud_ranges" in f:
            out["cloud_ranges.csv"].append(f"{p['cidr']},{p['org']}")
        if "hosting_asns" in f and p["asn"] not in seen_asn:
            out["hosting_asns.csv"].append(f"{p['asn']},{p['org']}")
            seen_asn.add(p["asn"])
        if "vpn_ranges" in f:
            out["vpn_ranges.csv"].append(f"{p['cidr']},{p['org']}")
        if "relay_ranges" in f:
            out["relay_ranges.csv"].append(f"{p['cidr']},{p['org']}")
        if "tor_exits" in f:
            out["tor_exits.txt"].extend(listed)
        if "open_proxies" in f:
            out["open_proxies.txt"].extend(listed)
        if "drop" in f:
            sbl = f"SBL{600000 + len(out['drop_v4.json']) + 1}"
            out["drop_v4.json"].append(json.dumps({"cidr": p["cidr"], "sblid": sbl, "rir": "ripencc"}))
            out["firehol_level1.netset"].append(p["cidr"])
    feeds = {k: "\n".join(v) + "\n" for k, v in out.items()}
    manifest = {"synthetic": True, "generated_from": "data/world.json via tools/build_world.py",
                "shape_reviewed": SHAPE_REVIEWED, "feeds": {}}
    for k, v in out.items():
        shaped, url, licence, refresh = SOURCES[k]
        rows = len([x for x in v if x]) - (1 if k.endswith(".csv") else 0)
        manifest["feeds"][k] = {"rows": rows, "shaped_like": shaped, "real_source_url": url, "licence": licence,
                                "production_refresh": refresh}
    feeds["manifest.json"] = json.dumps(manifest, indent=1) + "\n"
    feeds["README.md"] = readme(manifest)
    return feeds


def readme(manifest):
    lines = ["# data/feeds: synthetic IP intelligence", "",
             "Generated by `tools/build_world.py` from `data/world.json`; do not edit by hand. Every address is a",
             "documentation address (RFC 5737, RFC 3849) and every ASN a documentation ASN (RFC 5398). Nothing here",
             "describes a real network, and no lab ever downloads a real feed: the URLs below say what each file",
             "stands in for, and how often a production stack would refresh it.", "",
             f"Shapes last compared with the real feeds: {manifest['shape_reviewed']}. `manifest.json` holds the same table.", "",
             "| File | Rows | Shaped like | Real source | Licence (real source) | Production refresh |",
             "|---|---|---|---|---|---|"]
    for k, m in manifest["feeds"].items():
        lines.append(f"| `{k}` | {m['rows']} | {m['shaped_like']} | {m['real_source_url']} | {m['licence']} | {m['production_refresh']} |")
    lines += ["", "Gaps the world builds in on purpose (see `world.json`): a cloud whose ASN is on no hosting list",
              "(`cloud_gcp`), an IPv6 cloud /64 on no list at all (`cloud_v6`), open proxies fresher than the proxy list",
              "(`free_proxy`, 75% listed), and a privacy relay that the VPN list carries too (`private_relay`).",
              "`firehol_level1.netset` leaves out the bogon ranges the real list includes."]
    return "\n".join(lines) + "\n"


def main():
    with open(os.path.join(LAB, "data", "world.json")) as f:
        world = json.load(f)
    problems = validate(world)
    if problems:
        print("world.json breaks the rules:\n  " + "\n  ".join(problems))
        return 1
    feeds = build(world)
    os.makedirs(FEEDS, exist_ok=True)
    if "--check" in sys.argv:
        stale = [k for k, v in feeds.items() if not os.path.exists(os.path.join(FEEDS, k)) or open(os.path.join(FEEDS, k)).read() != v]
        print("feeds stale: " + ", ".join(stale) if stale else "feeds up to date")
        return 1 if stale else 0
    for k, v in feeds.items():
        with open(os.path.join(FEEDS, k), "w") as f:
            f.write(v)
    print("wrote " + ", ".join(feeds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
