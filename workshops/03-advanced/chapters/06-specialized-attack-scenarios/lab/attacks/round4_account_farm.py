"""Round 4 attack — fake-account farm.

The economy: mint many accounts cheaply (abuse free tiers, manufacture reviews,
stage future stuffing). Each registration looks fine alone. The default farm uses
disposable inboxes and a small device pool from one datacenter egress.
``--clean-emails`` swaps in real-looking domains to dodge the blocklist — but the
velocity and the device cluster remain.

    python attacks/round4_account_farm.py
    python attacks/round4_account_farm.py --clean-emails
"""

from __future__ import annotations

import argparse
import os
import random
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import BASE_URL, DATACENTER, headers, rand_ip, require_local

DISPOSABLE = ["mailinator.com", "guerrillamail.com", "10minutemail.com",
              "trashmail.com", "yopmail.com"]
CLEAN = ["mail.example", "webmail.example", "inbox.example"]


def run(count=20, clean_emails=False, fingerprints=3, base=BASE_URL):
    require_local(base)
    rng = random.Random(4)
    fps = [f"farm-fp-{i}" for i in range(fingerprints)]
    ip = rand_ip(DATACENTER, rng)          # one rented box for the whole farm
    domains = CLEAN if clean_emails else DISPOSABLE
    tally = {"allow": 0, "challenge": 0, "block": 0}
    for i in range(count):
        email = f"farm_{rng.randint(10000,99999)}@{rng.choice(domains)}"
        h = headers("bot", ip, fp=fps[i % len(fps)], session=f"farm-{i}")
        r = requests.post(f"{base}/register",
                          json={"email": email, "password": "P@ssw0rd123!"},
                          headers=h, timeout=5)
        tally[r.json().get("outcome", "?")] = tally.get(r.json().get("outcome", "?"), 0) + 1
    print(f"[farm] {count} registrations ({'clean' if clean_emails else 'disposable'} "
          f"emails) -> {tally}")
    print(f"[farm] accounts created: {tally['allow']}")
    return tally


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--clean-emails", action="store_true")
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    run(count=a.count, clean_emails=a.clean_emails, base=a.url)
