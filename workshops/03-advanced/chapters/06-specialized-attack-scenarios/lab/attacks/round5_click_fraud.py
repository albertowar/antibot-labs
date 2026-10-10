"""Round 5 attack — click / ad fraud.

The economy: drain an advertiser budget or inflate publisher payouts by faking ad
clicks. The default flood is General Invalid Traffic (GIVT): datacenter egress, no
referrer, no impression, junk User-Agent — identifiable by routine means. The
``--sivt`` variant is Sophisticated Invalid Traffic: it fires an impression first
and dresses as a residential browser with a referrer, but its engagement funnel is
hollow — it clicks instantly and in volume, which no real reader does.

    python attacks/round5_click_fraud.py          # GIVT flood
    python attacks/round5_click_fraud.py --sivt    # SIVT, humanized
"""

from __future__ import annotations

import argparse
import os
import random
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import BASE_URL, DATACENTER, RESIDENTIAL, REAL_UA, headers, rand_ip, require_local


def run(clicks=60, sivt=False, base=BASE_URL):
    require_local(base)
    rng = random.Random(5)
    tally = {"allow": 0, "block": 0}
    actor = "bot2" if sivt else "bot"
    for i in range(clicks):
        if sivt:
            ip = rand_ip(RESIDENTIAL, rng)
            sess = f"sivt-{i}"
            h = headers(actor, ip, session=sess, ua=REAL_UA,
                        referer="https://news.example/article")
            requests.post(f"{base}/track/impression", json={"campaign": "camp-1"},
                          headers=h, timeout=5)                 # impression, then...
            r = requests.post(f"{base}/track/click", json={"campaign": "camp-1"},
                              headers=h, timeout=5)              # ...instant click, hollow funnel
        else:
            ip = rand_ip(DATACENTER, rng)
            h = headers(actor, ip, session=f"givt-{i}", ua="bot/1.0", referer="")
            r = requests.post(f"{base}/track/click", json={"campaign": "camp-1"},
                              headers=h, timeout=5)
        tally[r.json().get("outcome", "?")] = tally.get(r.json().get("outcome", "?"), 0) + 1
    label = "SIVT (humanized)" if sivt else "GIVT (flood)"
    print(f"[clickfraud] {clicks} clicks, {label} -> {tally}")
    print(f"[clickfraud] fraudulent clicks counted as valid: {tally['allow']}")
    return tally


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--clicks", type=int, default=60)
    ap.add_argument("--sivt", action="store_true")
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    run(clicks=a.clicks, sivt=a.sivt, base=a.url)
