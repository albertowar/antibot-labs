"""
Build the published feeds a production stack would buy or download, from data/world.json:

    data/feeds/ip2asn.tsv          range_start  range_end  asn  country  org     (every pool)
    data/feeds/cloud_ranges.csv    cidr,provider                                 (type datacenter)
    data/feeds/hosting_asns.csv    asn,org                                       (type datacenter, proxy)
    data/feeds/vpn_ranges.csv      cidr,provider                                 (type vpn)
    data/feeds/relay_ranges.csv    cidr,provider                                 (type relay)
    data/feeds/tor_exits.txt       one address per line                          (type tor)
    data/feeds/open_proxies.txt    one address per line                          (type proxy)

Defenses read THESE, never world.json's `type`: that is the W1 Ch3 lesson. A
pool that is "residential_proxy" shows up in ip2asn as a residential ISP,
exactly as a real residential proxy does.

    python tools/build_world.py          # (re)write the feeds
    python tools/build_world.py --check  # exit 1 if the feeds are stale
"""

import ipaddress
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, ".."))
FEEDS = os.path.join(LAB, "data", "feeds")


def hosts(p):
    if "ips" in p:
        return list(p["ips"])
    net = ipaddress.ip_network(p["cidr"])
    base = int(net.network_address) + (1 if net.version == 4 and net.prefixlen < 31 else 0)
    return [str(ipaddress.ip_address(base + i)) for i in range(p.get("hosts", 50))]


def build(world):
    out = {"ip2asn.tsv": [], "cloud_ranges.csv": ["cidr,provider"], "hosting_asns.csv": ["asn,org"],
           "vpn_ranges.csv": ["cidr,provider"], "relay_ranges.csv": ["cidr,provider"], "tor_exits.txt": [], "open_proxies.txt": []}
    seen_asn = set()
    for name, p in world["pools"].items():
        net = ipaddress.ip_network(p["cidr"]) if "cidr" in p else None
        start, end = (str(net.network_address), str(net.broadcast_address)) if net else (p["ips"][0], p["ips"][-1])
        out["ip2asn.tsv"].append(f"{start}\t{end}\t{p['asn']}\t{p['country']}\t{p['org']}")
        t = p["type"]
        if t == "datacenter":
            out["cloud_ranges.csv"].append(f"{p['cidr']},{p['org']}")
        if t in ("datacenter", "proxy") and p["asn"] not in seen_asn:
            out["hosting_asns.csv"].append(f"{p['asn']},{p['org']}")
            seen_asn.add(p["asn"])
        if t == "vpn":
            out["vpn_ranges.csv"].append(f"{p['cidr']},{p['org']}")
        if t == "relay":
            out["relay_ranges.csv"].append(f"{p['cidr']},{p['org']}")
        if t == "tor":
            out["tor_exits.txt"].extend(hosts(p))
        if t == "proxy":
            out["open_proxies.txt"].extend(hosts(p))
    return {k: "\n".join(v) + "\n" for k, v in out.items()}


def main():
    with open(os.path.join(LAB, "data", "world.json")) as f:
        world = json.load(f)
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
