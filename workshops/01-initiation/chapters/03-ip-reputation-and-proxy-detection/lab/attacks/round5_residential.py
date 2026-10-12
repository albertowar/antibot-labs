"""
Chapter 3, Round 5 attack: rent a residential proxy network.

A different clean home connection for every request: 384 subscribers of six ISPs in six
countries, each in its own /64. Every address scores like your customers' because it IS a
customer's connection. No blocklist, no reputation score and no prefix bucket can tell.

What a proxy network cannot hide is that one session (one sid cookie) keeps arriving from
new homes, in new countries, seconds apart.

Your turn (red):
    --pin-country US    rent only US exits: no more country hops, but the session still
                        churns through addresses (session_ip_churn).
    --no-cookies        a fresh cookie jar for every request: each request is a brand-new
                        session from a brand-new clean address. The IP layer has nothing left.

Expected:   level 4: 120/120     level 5: 0-3/120 (pinned: 0-3/120)     --no-cookies at level 5: 120/120
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import ipkit  # noqa: E402
from labclient import world_pool  # noqa: E402  (labclient runs the localhost guard on import)

from labclient import WORLD, group_members  # noqa: E402

NETWORK = "residential_proxy_net"
PIN_COUNTRY = None      # e.g. "US"
KEEP_COOKIES = True


def run(pin_country=PIN_COUNTRY, keep_cookies=KEEP_COOKIES):
    r = ipkit.rng(5)
    pools = [p for p in group_members(NETWORK) if pin_country in (None, WORLD["pools"][p]["country"])]
    ips = [ip for p in pools for ip in world_pool(p)]
    name = "r5_residential" + (f"_{pin_country.lower()}" if pin_country else "") + ("" if keep_cookies else "_nocookies")
    return ipkit.scrape(name, lambda i: r.choice(ips), keep_cookies=keep_cookies,
                        extra={"countries": sorted({WORLD["pools"][p]["country"] for p in pools}), "exits": len(ips)})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin-country", default=PIN_COUNTRY)
    ap.add_argument("--no-cookies", action="store_true")
    a = ap.parse_args()
    ipkit.finish(run(a.pin_country, keep_cookies=KEEP_COOKIES and not a.no_cookies))
