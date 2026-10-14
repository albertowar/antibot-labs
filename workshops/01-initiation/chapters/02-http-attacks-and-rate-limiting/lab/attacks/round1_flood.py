"""
Chapter 2, Round 1 attack: the naive flood.

Hammer the catalog API from one cloud VM, eight requests at a time, with a real browser's
headers. Against the open store (and against Round 1's monitor, which only watches) it gets
all 120 products. The point of this round is to WATCH it: run it, then read the decision log
and the scoreboard to see the shape of the flood before you limit anything.

    python attacks/round1_flood.py                # scrape the catalog from one address
    python attacks/round1_flood.py --login        # credential-stuffing flood against /login

Expected:   level 0 and level 1 (monitor): 120/120 scraped, and every login attempt reaches
            the login logic. Level 1 tags the flood (flood_monitor:high_rate) but blocks
            nothing.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import ipkit  # noqa: E402  (labclient runs the localhost guard on import)

POOL = "cloud_vm"


def run_scrape():
    from labclient import world_pool
    ips = world_pool(POOL)
    return ipkit.scrape("r1_flood", lambda i: ips[0], extra={"pool": POOL})


def run_login():
    import _common
    from labclient import world_pool
    from demo_site.seed import weak_users
    ip = world_pool(POOL)[0]
    return _common.stuff("r1_login_flood", weak_users(), lambda i: ip)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--login", action="store_true", help="credential-stuffing flood against /login")
    a = ap.parse_args()
    if a.login:
        import _common
        _common.finish(run_login())
    else:
        ipkit.finish(run_scrape())
