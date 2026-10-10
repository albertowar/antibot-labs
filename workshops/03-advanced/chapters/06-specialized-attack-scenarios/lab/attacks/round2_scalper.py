"""Round 2 attack — scalping the limited drop.

The economy: capture scarce inventory and resell. The bot races the funnel at
machine speed: view, add, checkout with no human dwell, across a rotating pool of
accounts (sessions) but a small pool of devices (fingerprints), trying to sweep all
50 pairs before humans react. ``--skip-view`` goes straight to checkout, skipping
the funnel entirely.

    python attacks/round2_scalper.py              # 80 machine-speed attempts
    python attacks/round2_scalper.py --skip-view
"""

from __future__ import annotations

import argparse
import os
import random
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import BASE_URL, DATACENTER, headers, rand_ip, require_local

SKU = "lab-runner-9"


def run(attempts=80, skip_view=False, fingerprints=4, base=BASE_URL):
    require_local(base)
    rng = random.Random(2)
    fps = [f"scalp-fp-{i}" for i in range(fingerprints)]
    won = 0
    tally = {"allow": 0, "challenge": 0, "block": 0}
    for i in range(attempts):
        sess = f"scalp-sess-{i}"            # fresh session (stand-in for an account)
        fp = fps[i % len(fps)]
        ip = rand_ip(DATACENTER, rng)
        h = headers("bot", ip, fp=fp, session=sess)
        if not skip_view:
            requests.get(f"{base}/drop/{SKU}", headers=h, timeout=5)   # no dwell
            requests.post(f"{base}/cart/add", json={"sku": SKU}, headers=h, timeout=5)
        r = requests.post(f"{base}/checkout", json={}, headers=h, timeout=5)
        outcome = r.json().get("outcome", "?")
        tally[outcome] = tally.get(outcome, 0) + 1
        if outcome == "allow":
            won += 1
    print(f"[scalper] {attempts} attempts -> {tally}")
    print(f"[scalper] pairs won by the bot: {won} / 50")
    return won


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--attempts", type=int, default=80)
    ap.add_argument("--skip-view", action="store_true")
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    run(attempts=a.attempts, skip_view=a.skip_view, base=a.url)
