"""Legitimate-traffic simulator — the other half of every round's scoreboard.

Real customers do the same things the bots do: log in, buy the drop, browse the
catalogue, register, click an ad. They stamp ``X-Lab-Actor: human`` so the
scoreboard can tell a blocked bot from a blocked customer. A defense that blocks or
challenges these people is a cost, however many bots it stops.

All users, fingerprints, IPs and sessions are synthetic. Humans pace themselves:
the drop buyers dwell on the product page, and the ad clickers read before they
click, so a correct defense lets them through while catching the machine-speed bot.

    python tools/legit_traffic.py            # run every round's humans, summarise
    python tools/legit_traffic.py --round 2
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
DATA = os.path.join(LAB_DIR, "data")
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
from _common import BASE_URL, REAL_UA, headers, require_local  # noqa: E402

SKU = "lab-runner-9"


def _tally(outcomes):
    t = {"allow": 0, "challenge": 0, "block": 0, "invalid": 0}
    for o in outcomes:
        t[o] = t.get(o, 0) + 1
    return t


def _res_ip(i):   # a distinct residential IP per human
    return f"198.51.100.{(i % 253) + 1}"


def humans_round1(base):
    with open(os.path.join(DATA, "humans.json")) as fh:
        people = json.load(fh)
    out = []
    for i, p in enumerate(people):
        r = requests.post(f"{base}/login", json={"email": p["email"], "password": p["password"]},
                          headers=headers("human", _res_ip(i)), timeout=5)
        out.append(r.json().get("outcome", "?"))
    return _tally(out)


def humans_round2(base, n=40):
    def buy(i):
        h = headers("human", _res_ip(i), fp=f"human-fp-{i}", session=f"human-sess-{i}")
        requests.get(f"{base}/drop/{SKU}", headers=h, timeout=5)
        time.sleep(random.uniform(1.3, 1.8))          # human dwell on the product page
        requests.post(f"{base}/cart/add", json={"sku": SKU}, headers=h, timeout=5)
        r = requests.post(f"{base}/checkout", json={}, headers=h, timeout=5)
        return r.json().get("outcome", "?")
    with ThreadPoolExecutor(max_workers=20) as ex:
        out = list(ex.map(buy, range(n)))
    return _tally(out)


def humans_round3(base, n=15):
    rng = random.Random(33)
    out = []
    for i in range(n):
        h = headers("human", _res_ip(i), fp=f"human-fp-{i}", session=f"shopper-{i}")
        out.append(requests.get(f"{base}/products?page=1", headers=h, timeout=5).json().get("outcome", "?"))
        for sku in rng.sample([f"cat-{j:03d}" for j in range(1, 61)], rng.randint(4, 7)):
            out.append(requests.get(f"{base}/product/{sku}", headers=h, timeout=5).json().get("outcome", "?"))
    return _tally(out)


def humans_round4(base, n=10):
    out = []
    for i in range(n):           # each a first-time customer: own device, own egress
        h = headers("human", _res_ip(i), fp=f"newuser-fp-{i}", session=f"signup-{i}")
        email = f"real_person_{i}@mail.example"
        r = requests.post(f"{base}/register", json={"email": email, "password": "T7rue-Horse-Battery!9"},
                          headers=h, timeout=5)
        out.append(r.json().get("outcome", "?"))
    return _tally(out)


def humans_round5(base, n=15):
    def clickthrough(i):
        h = headers("human", _res_ip(i), session=f"reader-{i}", ua=REAL_UA,
                    referer="https://news.example/article")
        requests.post(f"{base}/track/impression", json={"campaign": "camp-1"}, headers=h, timeout=5)
        time.sleep(random.uniform(0.45, 0.9))        # reads the page before clicking
        r = requests.post(f"{base}/track/click", json={"campaign": "camp-1"}, headers=h, timeout=5)
        return r.json().get("outcome", "?")
    with ThreadPoolExecutor(max_workers=20) as ex:
        out = list(ex.map(clickthrough, range(n)))
    return _tally(out)


ROUNDS = {1: humans_round1, 2: humans_round2, 3: humans_round3,
          4: humans_round4, 5: humans_round5}


def run_humans(round_, base=BASE_URL):
    require_local(base)
    return ROUNDS[round_](base)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, choices=[1, 2, 3, 4, 5], default=None)
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    rounds = [a.round] if a.round else [1, 2, 3, 4, 5]
    for r in rounds:
        print(f"round {r} humans: {run_humans(r, a.url)}")
