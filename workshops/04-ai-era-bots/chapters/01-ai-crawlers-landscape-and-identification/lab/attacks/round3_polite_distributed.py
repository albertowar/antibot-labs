"""Round 3 attack: behave like thirty people.

Behaviour scoring catches the metronome. So the crawler stops being one: it splits the catalog
across thirty residential-looking addresses, each of which opens the catalog page, follows
links to its handful of products in random order, fetches the stylesheet, script and images
like a browser and pauses a human-ish random interval between pages. Per address there is
almost nothing to score.

What it does not do by default is hold a session cookie, and all thirty share one User-Agent
on one ISP. The reference Round 3 solution correlates cookie-less clients by (User-Agent, ASN)
and trips once that cluster has fetched a third of the catalog. The --cookies flag removes that
last tell (the checkpoint runs it from a second ISP, so the two campaigns do not share a
cluster). What is left is the chapter's residual: at the HTTP level a polite, distributed,
cookie-holding crawler on residential addresses is a crowd of shoppers. W4 Ch2 and Ch3 take it
from there.

    python attacks/round3_polite_distributed.py              # 30 ISP IPs, assets, jitter, links, no cookies
    python attacks/round3_polite_distributed.py --cookies --pool home_eu   # a second campaign on another ISP, with cookies
    python attacks/round3_polite_distributed.py --speed 0.2  # less patient (shorter pauses)
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import UA, Crawler, Tally, finish, world_pool  # noqa: E402


def run(ips: int = 30, pool: str = "home_fiber", cookies: bool = False, speed: float = 1.0, seed: int = 3) -> dict:
    rng = random.Random(seed)
    addrs = world_pool(pool)[10:10 + ips]
    name = "bot:polite-30-cookies" if cookies else "bot:polite-30"
    coordinator = Crawler(name, addrs[0], UA["stealth-chrome"])
    targets = coordinator.sitemap_paths()
    rng.shuffle(targets)
    tally = Tally(len(targets))
    shares = [targets[i::ips] for i in range(ips)]          # split the catalog across workers

    def worker(i):
        bot = Crawler(name, addrs[i], UA["stealth-chrome"], cookies=cookies)
        wrng = random.Random(seed * 100 + i)

        def pause():
            time.sleep(wrng.uniform(0.3, 1.2) * speed)

        r = bot.get(f"/products?page={wrng.randint(1, 5)}")             # arrive via the catalog
        if r.status_code == 200:
            bot.fetch_assets(r.text, limit=4)
        pause()
        for path in shares[i]:
            r = bot.get(path)
            tally.add(path, r.status_code)
            if r.status_code == 200:
                bot.fetch_assets(r.text)
            pause()

    with ThreadPoolExecutor(max_workers=ips) as ex:
        list(ex.map(worker, range(ips)))
    return tally.report(f"round3 polite crawler over {ips} {pool} IPs{' +cookies' if cookies else ''}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ips", type=int, default=30)
    ap.add_argument("--pool", default="home_fiber", choices=["home_fiber", "home_eu"])
    ap.add_argument("--cookies", action="store_true")
    ap.add_argument("--speed", type=float, default=1.0)
    a = ap.parse_args()
    finish(run(a.ips, a.pool, a.cookies, a.speed))
