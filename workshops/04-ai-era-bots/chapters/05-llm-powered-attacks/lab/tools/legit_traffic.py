"""Legitimate-traffic simulator — the other half of every round's scoreboard.

Real customers do the same things the bots do: write a review, register, browse
the catalogue, read a product summary. They stamp ``X-Lab-Actor: human`` so the
scoreboard can tell a blocked bot from a blocked customer. A defense that blocks
these people is a cost, however many bots it stops. A *challenge* (a held review,
a step-up, a puzzle a person can solve) is friction, not failure — counted
separately.

All accounts, fingerprints, IPs and sessions are synthetic. Humans pace
themselves and each use their own device and egress, so a correct defense lets
them through while catching the machine-speed, device-sharing bot.

    python tools/legit_traffic.py            # run every round's humans, summarise
    python tools/legit_traffic.py --round 2
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
DATA = os.path.join(LAB_DIR, "data")
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
sys.path.insert(0, LAB_DIR)
from _common import BASE_URL, headers, require_local  # noqa: E402
from defenses.challenge_gate import pow_solve  # noqa: E402


def _tally(outcomes):
    t = {"allow": 0, "challenge": 0, "block": 0, "invalid": 0}
    for o in outcomes:
        t[o] = t.get(o, 0) + 1
    return t


def _res_ip(i):   # a distinct residential IP per human
    return f"198.51.100.{(i % 253) + 1}"


def _human_reviews(cohort, base, round_):
    with open(os.path.join(DATA, "human_reviews.json")) as fh:
        people = json.load(fh)[cohort]
    out = []
    for p in people:
        r = requests.post(f"{base}/review",
                          json={"sku": p["sku"], "rating": p["rating"], "text": p["text"]},
                          headers=headers("human", _res_ip(p["ip_index"]), fp=p["fp"],
                                          user=p["email"], round_=round_), timeout=10)
        out.append(r.json().get("outcome", "?"))
    return _tally(out)


def humans_round1(base):
    return _human_reviews("round1", base, 1)


def humans_round4(base):
    return _human_reviews("round4", base, 4)


def humans_round2(base, n=20):
    """First-time registrants, each on their own device and residential IP. Two
    (i < 2) ask for the accessible text puzzle — they must never be blocked for it."""
    out = []
    for i in range(n):
        mode = "text" if i < 2 else "image"
        h = headers("human", _res_ip(i), fp=f"human-reg-fp-{i}", session=f"signup-{i}")
        email = f"new_customer_{i:02d}@mail.example"
        r = requests.post(f"{base}/register",
                          json={"email": email, "password": "Human-Pass-" + str(i), "mode": mode},
                          headers=h, timeout=15).json()
        if r.get("outcome") == "challenge" and r.get("challenge"):
            chal = r["challenge"]
            ans = requests.get(f"{base}/lab/answer/{chal['token']}", timeout=5).json()["answer"]
            nonce = pow_solve(chal["token"], chal["pow_bits"]) if chal.get("pow_bits") else ""
            r = requests.post(f"{base}/register",
                              json={"email": email, "password": "Human-Pass-" + str(i), "mode": mode,
                                    "challenge_token": chal["token"], "answer": ans, "nonce": nonce},
                              headers=h, timeout=15).json()
            # A person who had to solve a puzzle = friction, record as challenge
            out.append("challenge" if r.get("outcome") == "allow" else r.get("outcome", "?"))
        else:
            out.append(r.get("outcome", "?"))
    return _tally(out)


def humans_round3(base, n=15):
    """Shoppers browse a page or two and open a few products. Low coverage, their
    own session each, and they never touch the hidden honeypot SKUs."""
    import random
    rng = random.Random(33)
    out = []
    for i in range(n):
        h = headers("human", _res_ip(i), session=f"shopper-{i}")
        requests.get(f"{base}/catalog?page=1", headers=h, timeout=10)
        out.append("allow")
        for sku in rng.sample([f"cat-{j:03d}" for j in range(1, 61)], rng.randint(2, 5)):
            out.append(requests.get(f"{base}/product/{sku}", headers=h, timeout=10)
                       .json().get("outcome", "?"))
    return _tally(out)


ROUNDS = {1: humans_round1, 2: humans_round2, 3: humans_round3, 4: humans_round4}


def run_humans(round_, base=BASE_URL):
    require_local(base)
    return ROUNDS[round_](base)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, choices=[1, 2, 3, 4], default=None)
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    for r in ([a.round] if a.round else [1, 2, 3, 4]):
        print(f"round {r} humans: {run_humans(r, a.url)}")
