"""Round 3 attack — adversarial catalogue scraping.

The economy: harvest the whole catalogue (prices, assortment). The scraper is
breadth-first: it walks every listing page, then every product SKU, then probes a
few guessed internal SKUs. Stealth headers and a residential IP do not hide the one
thing it cannot avoid — it wants *coverage*, and a shopper does not.

    python attacks/round3_scraper.py
"""

from __future__ import annotations

import argparse
import os
import random
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import BASE_URL, RESIDENTIAL, headers, rand_ip, require_local


def run(base=BASE_URL):
    require_local(base)
    rng = random.Random(3)
    ip = rand_ip(RESIDENTIAL, rng)
    sess = "scraper-sess"
    h = headers("bot", ip, fp="scraper-fp", session=sess)
    harvested, blocked_at = [], None

    def pull(path, label):
        nonlocal blocked_at
        r = requests.get(f"{base}{path}", headers=h, timeout=5)
        body = r.json()
        if body.get("outcome") == "allow":
            harvested.append(label)
            return True
        if blocked_at is None:
            blocked_at = (label, body.get("reason", ""))
        return False

    for page in range(1, 7):               # listing pages
        pull(f"/products?page={page}", f"page{page}")
    for i in range(1, 61):                  # every catalogue SKU
        pull(f"/product/cat-{i:03d}", f"cat-{i:03d}")
    for i in range(1, 5):                   # guessed internal SKUs (honeypots)
        pull(f"/product/hp-{i:03d}", f"hp-{i:03d}")

    print(f"[scraper] catalogue items + pages harvested: {len(harvested)}")
    if blocked_at:
        print(f"[scraper] first blocked at {blocked_at[0]}: {blocked_at[1]}")
    else:
        print("[scraper] never blocked — whole catalogue exfiltrated")
    return len(harvested)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=BASE_URL)
    run(base=ap.parse_args().url)
