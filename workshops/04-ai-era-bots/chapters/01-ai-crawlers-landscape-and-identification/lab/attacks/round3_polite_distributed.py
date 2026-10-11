"""Round 3 attack: behave like thirty people.

Behaviour scoring catches the metronome. So the crawler stops being one: it splits the
catalog across thirty residential-looking addresses, each of which opens the catalog
page, follows links to its handful of products in random order, fetches the CSS, JS
and logo like a browser and pauses a human-ish random interval between pages. Per
address there is almost nothing to score.

What it does not do by default is hold a session cookie, and all thirty share one
User-Agent on one ISP. The reference Round 3 solution correlates cookie-less clients
by (User-Agent, ASN) and trips once that cluster has fetched a third of the catalog.
The --cookies flag removes that last tell. What is left is the chapter's residual:
at the HTTP level a polite, distributed, cookie-holding crawler on residential
addresses is a crowd of shoppers. W4 Ch2 and Ch3 take it from there.

    python attacks/round3_polite_distributed.py              # 30 ISP IPs, assets, jitter, links, no cookies
    python attacks/round3_polite_distributed.py --cookies    # each address keeps its session cookie
    python attacks/round3_polite_distributed.py --pool cloud-a
    python attacks/round3_polite_distributed.py --speed 0.2  # less patient (shorter pauses)
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import BASE_URL, POOLS, UA, Tally, catalog_size, fetch_assets, headers, require_local, sitemap_paths  # noqa: E402


def run(base: str = BASE_URL, ips: int = 30, pool: str = "home-isp", cookies: bool = False,
        speed: float = 1.0, seed: int = 3) -> dict:
    require_local(base)
    rng = random.Random(seed)
    addrs = POOLS[pool][60:60 + ips]
    size = catalog_size(base)
    tally = Tally(size)
    coordinator = headers("attack:round3", addrs[0], UA["stealth-chrome"])
    targets = sitemap_paths(requests.get(f"{base}/sitemap.xml", headers=coordinator, timeout=5).text)
    rng.shuffle(targets)
    shares = [targets[i::ips] for i in range(ips)]          # split the catalog across workers

    def worker(i):
        ip = addrs[i]
        hdrs = headers("attack:round3", ip, UA["stealth-chrome"])
        s = requests.Session() if cookies else None
        get = (s.get if s else requests.get)
        wrng = random.Random(seed * 100 + i)

        def pause():
            time.sleep(wrng.uniform(0.3, 1.2) * speed)

        page_no = wrng.randint(1, 6)
        r = get(f"{base}/products?page={page_no}", headers=hdrs, timeout=5)  # arrive via the catalog
        if r.status_code == 200:
            fetch_assets(s or requests, base, r.text, hdrs)
        pause()
        for path in shares[i]:
            r = get(f"{base}{path}", headers=hdrs, timeout=5)
            tally.add(path, r.status_code)
            if r.status_code == 200:
                fetch_assets(s or requests, base, r.text, hdrs)
            pause()

    with ThreadPoolExecutor(max_workers=ips) as ex:
        list(ex.map(worker, range(ips)))
    return tally.report(f"round3 polite crawler over {ips} {pool} IPs{' +cookies' if cookies else ''}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=BASE_URL)
    ap.add_argument("--ips", type=int, default=30)
    ap.add_argument("--pool", default="home-isp", choices=["home-isp", "mobile-cgnat", "cloud-a", "hosting-b"])
    ap.add_argument("--cookies", action="store_true")
    ap.add_argument("--speed", type=float, default=1.0)
    a = ap.parse_args()
    run(a.url, a.ips, a.pool, a.cookies, a.speed)
