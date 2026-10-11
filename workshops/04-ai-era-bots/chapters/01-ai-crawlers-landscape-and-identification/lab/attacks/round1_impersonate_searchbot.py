"""Round 1 attack: wear the badge of a crawler the policy allows.

Round 1's robots.txt lets search crawlers in and keeps training crawlers out, and the
registry enforces it by token. A token is a string in a header. This scraper sends
OAI-SearchBot's exact User-Agent from a rented cloud address, never reads robots.txt,
and walks the sitemap. At DEFENSE_LEVEL=1 it is classified "search, allowed" and takes
the whole catalog. Round 2 checks whether the badge is real.

    python attacks/round1_impersonate_searchbot.py                  # OAI-SearchBot from a cloud VM
    python attacks/round1_impersonate_searchbot.py --token Googlebot # a token verified by rDNS
    python attacks/round1_impersonate_searchbot.py --token Googlebot --fake-ptr
        # from 192.0.2.150, whose PTR says googlebot.com but whose forward lookup does
        # not come back to it: passes a PTR-only check, fails forward confirmation
    python attacks/round1_impersonate_searchbot.py --token GPTBot    # wrong badge: training is disallowed
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import BASE_URL, POOLS, UA, Tally, catalog_size, headers, require_local, sitemap_paths  # noqa: E402

FAKE_PTR_IP = "192.0.2.150"


def run(base: str = BASE_URL, token: str = "OAI-SearchBot", pool: str = "cloud-a",
        fake_ptr: bool = False, delay: float = 0.03) -> dict:
    require_local(base)
    ip = FAKE_PTR_IP if fake_ptr else POOLS[pool][7]
    hdrs = headers("attack:round1", ip, UA[token])
    tally = Tally(catalog_size(base))
    r = requests.get(f"{base}/sitemap.xml", headers=hdrs, timeout=5)     # never robots.txt
    for path in sitemap_paths(r.text):
        resp = requests.get(f"{base}{path}", headers=hdrs, timeout=5)
        tally.add(path, resp.status_code)
        time.sleep(delay)
    return tally.report(f"round1 impersonating {token} from {ip}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=BASE_URL)
    ap.add_argument("--token", default="OAI-SearchBot", choices=["OAI-SearchBot", "Googlebot", "GPTBot", "PerplexityBot", "ClaudeBot"])
    ap.add_argument("--pool", default="cloud-a", choices=["cloud-a", "hosting-b", "home-isp"])
    ap.add_argument("--fake-ptr", action="store_true")
    a = ap.parse_args()
    run(a.url, a.token, a.pool, a.fake_ptr)
