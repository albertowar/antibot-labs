"""
Chapter 3, Round 1 attack: scrape the catalog from one cloud VM.

All 120 products from ONE address, eight requests at a time. Against no defense it gets
everything; against the Round 1 per-IP limit (30 a minute, burst 20) it gets its burst and
little else.

Your turn (red): rent an IPv6 VPS instead. A VPS gets a whole /64, and every request can
come from a different address in it, so a per-address limit never sees the same IP twice.

    python attacks/round1_single_ip.py                    # POOL = "cloud_vm", one address
    python attacks/round1_single_ip.py --pool cloud_v6    # a fresh address in one /64 per request

Expected:   level 0: 120/120     level 1: ~20/120     --pool cloud_v6 at level 1: 120/120, at level 5 (--no-cookies): ~15/120
The IPv6 variant comes back in Round 5, where prefix_limit counts per /64.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import ipkit  # noqa: E402
from labclient import world_pool  # noqa: E402  (labclient runs the localhost guard on import)

POOL = "cloud_vm"


def run(pool=POOL, keep_cookies=True):
    ips = world_pool(pool)
    if pool == "cloud_vm":
        next_ip = lambda i: ips[0]                         # noqa: E731  one VM, one address
    else:
        next_ip = lambda i: ips[(i + 1) % len(ips)]        # noqa: E731  a new address every request
    return ipkit.scrape(f"r1_{pool}", next_ip, keep_cookies=keep_cookies, extra={"pool": pool})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default=POOL)
    ap.add_argument("--no-cookies", action="store_true", help="a fresh cookie jar per request")
    a = ap.parse_args()
    ipkit.finish(run(a.pool, keep_cookies=not a.no_cookies))
