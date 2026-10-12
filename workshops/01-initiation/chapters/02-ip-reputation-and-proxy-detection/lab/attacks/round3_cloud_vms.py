"""
Chapter 2, Round 3 attack: a fleet of brand-new cloud VMs.

80 freshly rented VMs on two cloud providers, one or two requests each. A VM bought five
minutes ago is on no blocklist, and no single address comes close to the rate limit.
What gives it away is the network it lives on: published cloud ranges and hosting ASNs.

Your turn (red): in defenses/policy.py set IP_POINTS["datacenter"] = 30 and rerun. One of
the two providers (cloud_gcp) publishes its ranges but its ASN is on no community hosting
list, so its VMs score 30: monitor, served. Every free source has gaps.

    python attacks/round3_cloud_vms.py
    python -m defenses.ip_reputation 198.51.100.97      # why a cloud_gcp VM scores what it does

Expected:   level 2: 120/120     level 3: 0/120
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import ipkit  # noqa: E402
from labclient import world_pool  # noqa: E402  (labclient runs the localhost guard on import)

POOLS = ["cloud_vm", "cloud_gcp"]


def run(pools=POOLS):
    r = ipkit.rng(3)
    ips = [ip for p in pools for ip in world_pool(p)]
    return ipkit.scrape("r3_cloud_vms", lambda i: r.choice(ips), extra={"pools": pools})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pools", default=",".join(POOLS))
    ipkit.finish(run(ap.parse_args().pools.split(",")))
