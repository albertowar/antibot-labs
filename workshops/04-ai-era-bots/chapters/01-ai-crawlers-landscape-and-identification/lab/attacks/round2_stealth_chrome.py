"""Round 2 attack: claim nobody. The undeclared crawler.

Once badges are verified, the cheapest move is to stop wearing one. This crawler sends
a plain Chrome User-Agent (the exact string Cloudflare attributed to Perplexity's
undeclared crawler in August 2025), rotates across a handful of rented cloud
addresses, never fetches robots.txt, walks the sitemap in order, and asks for HTML
only. At DEFENSE_LEVEL=2 there is no claim to verify, so it takes everything.

Round 3 scores behaviour. The flags below are the evolved variants to try after that:
each hides one tell, and the checkpoint shows what is left.

    python attacks/round2_stealth_chrome.py                 # 4 cloud IPs, HTML only, metronome, sitemap order
    python attacks/round2_stealth_chrome.py --assets        # also fetch css/js/logo like a browser
    python attacks/round2_stealth_chrome.py --jitter        # random gaps instead of a fixed delay
    python attacks/round2_stealth_chrome.py --shuffle       # random order instead of the sitemap's
    python attacks/round2_stealth_chrome.py --ips 12        # spread thinner
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import BASE_URL, POOLS, UA, Tally, catalog_size, fetch_assets, headers, require_local, sitemap_paths  # noqa: E402


def run(base: str = BASE_URL, ips: int = 4, pool: str = "cloud-a", assets: bool = False,
        jitter: bool = False, shuffle: bool = False, delay: float = 0.03, seed: int = 2) -> dict:
    require_local(base)
    rng = random.Random(seed)
    addrs = POOLS[pool][20:20 + ips]
    tally = Tally(catalog_size(base))
    first = headers("attack:round2", addrs[0], UA["stealth-chrome"])
    paths = sitemap_paths(requests.get(f"{base}/sitemap.xml", headers=first, timeout=5).text)
    if shuffle:
        rng.shuffle(paths)
    session = requests.Session()
    session.cookies.clear()
    for i, path in enumerate(paths):
        hdrs = headers("attack:round2", addrs[i % len(addrs)], UA["stealth-chrome"])
        resp = requests.get(f"{base}{path}", headers=hdrs, timeout=5)   # no session: no cookie
        tally.add(path, resp.status_code)
        if assets and resp.status_code == 200:
            fetch_assets(session, base, resp.text, hdrs)
        time.sleep(rng.uniform(0.0, 4 * delay) if jitter else delay)
    flags = " ".join(f for f, on in [("assets", assets), ("jitter", jitter), ("shuffle", shuffle)] if on)
    return tally.report(f"round2 stealth Chrome over {len(addrs)} {pool} IPs{' +' + flags if flags else ''}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=BASE_URL)
    ap.add_argument("--ips", type=int, default=4)
    ap.add_argument("--pool", default="cloud-a", choices=["cloud-a", "hosting-b", "home-isp"])
    ap.add_argument("--assets", action="store_true")
    ap.add_argument("--jitter", action="store_true")
    ap.add_argument("--shuffle", action="store_true")
    a = ap.parse_args()
    run(a.url, a.ips, a.pool, a.assets, a.jitter, a.shuffle)
