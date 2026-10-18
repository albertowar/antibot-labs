"""Round 1 attack: wear the badge of a crawler the policy allows.

Round 1's robots policy lets search crawlers in and keeps training crawlers out, and the
registry enforces it by token. A token is a string in a header. This scraper sends
OAI-SearchBot's exact User-Agent from a rented cloud address, never reads robots.txt, and
walks the sitemap. At DEFENSE_LEVEL=1 it is classified "search, allowed" and takes the whole
catalog. Round 2 checks whether the badge is real.

    python attacks/round1_impersonate_searchbot.py                  # OAI-SearchBot from a cloud VM
    python attacks/round1_impersonate_searchbot.py --token Googlebot # a token verified by rDNS
    python attacks/round1_impersonate_searchbot.py --token Googlebot --fake-ptr
        # from 203.0.113.121, whose PTR says googlebot.com but whose forward lookup does
        # not come back to it (the name has no A record): passes a PTR-only check, fails forward confirmation
    python attacks/round1_impersonate_searchbot.py --token GPTBot    # wrong badge: training is disallowed
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import UA, Crawler, Tally, finish, pool_ip  # noqa: E402

FAKE_PTR_IP = ("hosting_asn", 56)       # 203.0.113.121, see tools/fixtures/dns_zones.json
IMPERSONATOR_INDEX = 35                 # 203.0.113.36 in cloud_vm: inside no operator's published range


def run(token: str = "OAI-SearchBot", pool: str = "cloud_vm", fake_ptr: bool = False, delay: float = 0.03) -> dict:
    ip = pool_ip(*FAKE_PTR_IP) if fake_ptr else pool_ip(pool, IMPERSONATOR_INDEX)
    bot = Crawler("bot:impersonator", ip, UA[token])
    paths = bot.sitemap_paths()                      # never robots.txt
    tally = Tally(len(paths))
    for path in paths:
        tally.add(path, bot.get(path).status_code)
        time.sleep(delay)
    return tally.report(f"round1 impersonating {token} from {ip}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--token", default="OAI-SearchBot", choices=["OAI-SearchBot", "Googlebot", "GPTBot", "PerplexityBot", "ClaudeBot"])
    ap.add_argument("--pool", default="cloud_vm", choices=["cloud_vm", "hosting_asn", "home_fiber"])
    ap.add_argument("--fake-ptr", action="store_true")
    a = ap.parse_args()
    finish(run(a.token, a.pool, a.fake_ptr))
