"""
Chapter 2, Round 4 attack: the same cloud fleet, plus one header.

Every request carries an X-Forwarded-For naming a random home broadband address. The edge
appends the real source, so the origin is told

    X-Forwarded-For: 192.0.2.201, 203.0.113.17
                     ^ the attacker wrote this   ^ the edge saw this

and an app that reads the leftmost entry scores a clean home user. The rate limit, the
blocklists and the reputation score all key on that one value, so one header bypasses
every IP-based layer at once.

Your turn (red):
    --spoof-as 127.0.0.1        claim to be internal: reputation skips internal addresses,
                                but every request lands in the SAME rate-limit bucket. Partial.
    --spoof-as internal-random  how the attacker fixes that: a different 10.x address per
                                request, each with a fresh bucket.

Expected:   level 3: ~100 % (127.0.0.1: ~20 %)     level 4: 0 % for every variant
"""

import ipaddress

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import ipkit  # noqa: E402
from labclient import world_pool  # noqa: E402  (labclient runs the localhost guard on import)

SPOOF_AS = "home"       # "home" | "127.0.0.1" (or any fixed address) | "internal-random"
POOLS = ["cloud_vm", "cloud_gcp"]


def run(spoof_as=SPOOF_AS):
    r = ipkit.rng(4)
    ips = [ip for p in POOLS for ip in world_pool(p)]
    fakes = world_pool("home_eu") + world_pool("home_v6")     # nobody in the shopper population lives here
    if spoof_as == "home":
        xff = lambda i: r.choice(fakes)                                                  # noqa: E731
    elif spoof_as == "internal-random":
        xff = lambda i: str(ipaddress.ip_address(0x0A000000 + r.randrange(1, 1 << 24)))  # noqa: E731
    else:
        xff = lambda i: spoof_as                                                         # noqa: E731
    name = {"home": "r4_xff_home", "internal-random": "r4_xff_internal_random"}.get(spoof_as, "r4_xff_fixed")
    return ipkit.scrape(name, lambda i: r.choice(ips), xff=xff, extra={"spoof_as": spoof_as})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--spoof-as", default=SPOOF_AS)
    ipkit.finish(run(ap.parse_args().spoof_as))
