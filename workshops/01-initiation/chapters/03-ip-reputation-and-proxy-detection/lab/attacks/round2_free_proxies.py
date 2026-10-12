"""
Chapter 3, Round 2 attack: rotate through a free public proxy list.

The scraper spreads its 120 requests over 60 "free proxies", two or three each, so the
per-IP limit never trips. Free proxies are free for a reason: in this world 40 % of the list
is dead. A dead proxy costs a real scraper a connection timeout (about 10 s) before it moves
on; here it is skipped before any request is sent and counted in dead_proxy_skipped.

The proxies are addresses the store pretends to see (pool free_proxy in data/world.json).
Nothing is downloaded and nothing leaves this machine. Real lists such as
TheSpeedX/PROXY-List are discussed in the chapter; no lab script ever fetches one.

Your turn (red):
    python attacks/round2_free_proxies.py --pool tor_exit           # Tor: free, reliable, and every exit is published
    python attacks/round2_free_proxies.py --pool bulletproof_host   # "bulletproof" hosting, on Spamhaus DROP

Expected:   level 1: ~100 %     level 2: ~25 % (the proxies newer than your copy of the list)
            tor_exit and bulletproof_host at level 2: 0 %
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import ipkit  # noqa: E402
from labclient import world_pool  # noqa: E402  (labclient runs the localhost guard on import)

POOL = "free_proxy"
DEAD_SHARE = 0.4
TIMEOUT_S = 10          # what one dead proxy costs a real scraper


def run(pool=POOL):
    r = ipkit.rng(2)
    ips = world_pool(pool)
    dead = set(r.sample(ips, int(len(ips) * DEAD_SHARE))) if pool == "free_proxy" else set()
    alive = [ip for ip in ips if ip not in dead]
    skipped = {"n": 0}

    def next_ip(i):
        while True:                                   # try proxies until one answers
            ip = r.choice(ips)
            if ip not in dead:
                return ip
            skipped["n"] += 1

    out = ipkit.scrape(f"r2_{pool}", next_ip, extra={"pool": pool, "proxies_alive": len(alive)})
    out.update(dead_proxy_skipped=skipped["n"], timeout_s_lost=skipped["n"] * TIMEOUT_S)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default=POOL)
    ipkit.finish(run(ap.parse_args().pool))
