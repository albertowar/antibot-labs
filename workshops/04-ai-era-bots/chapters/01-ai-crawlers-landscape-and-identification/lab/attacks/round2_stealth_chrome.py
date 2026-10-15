"""Round 2 attack: claim nobody. The undeclared crawler.

Once badges are verified, the cheapest move is to stop wearing one. This crawler sends a plain
Chrome User-Agent (the exact string Cloudflare attributed to Perplexity's undeclared crawler in
August 2025), rotates across a handful of rented cloud addresses, never fetches robots.txt,
walks the sitemap in order, and asks for HTML only. At DEFENSE_LEVEL=2 there is no claim to
verify, so it takes everything.

Round 3 scores behaviour. The flags below are the evolved variants to try after that: each
hides one tell, and the checkpoint shows what is left.

    python attacks/round2_stealth_chrome.py                 # 4 cloud IPs, HTML only, metronome, sitemap order
    python attacks/round2_stealth_chrome.py --assets        # also fetch css/js/images like a browser
    python attacks/round2_stealth_chrome.py --jitter        # random gaps instead of a fixed delay
    python attacks/round2_stealth_chrome.py --shuffle       # random order instead of the sitemap's
    python attacks/round2_stealth_chrome.py --ips 12        # spread thinner (up to 20)
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import UA, Crawler, Tally, finish, world_pool  # noqa: E402


def run(ips: int = 4, assets: bool = False, jitter: bool = False,
        shuffle: bool = False, delay: float = 0.03, seed: int = 2) -> dict:
    rng = random.Random(seed)
    addrs = world_pool("cloud_vm")[10:10 + min(ips, 20)]       # .11-.30: clear of every operator's slice
    bots = [Crawler("bot:stealth-chrome", ip, UA["stealth-chrome"]) for ip in addrs]
    paths = bots[0].sitemap_paths()
    if shuffle:
        rng.shuffle(paths)
    tally = Tally(len(paths))
    for i, path in enumerate(paths):
        bot = bots[i % len(bots)]                                # no cookie jar: every request is a stranger
        resp = bot.get(path)
        tally.add(path, resp.status_code)
        if assets and resp.status_code == 200:
            bot.fetch_assets(resp.text)
        time.sleep(rng.uniform(0.0, 4 * delay) if jitter else delay)
    flags = " ".join(f for f, on in [("assets", assets), ("jitter", jitter), ("shuffle", shuffle)] if on)
    return tally.report(f"round2 stealth Chrome over {len(addrs)} cloud IPs{' +' + flags if flags else ''}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ips", type=int, default=4)
    ap.add_argument("--assets", action="store_true")
    ap.add_argument("--jitter", action="store_true")
    ap.add_argument("--shuffle", action="store_true")
    a = ap.parse_args()
    finish(run(a.ips, a.assets, a.jitter, a.shuffle))
