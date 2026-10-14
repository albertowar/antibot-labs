"""
Round 4 attack: a fake-account farm.

The economy: mint many accounts cheaply (free-tier abuse, review inflation, accounts staged for later
stuffing). Each registration is fine alone; the farm shares infrastructure. This one rents a single
hosting address and three browser profiles (device cookies), and registers through POST /api/register.

    python attacks/round4_account_farm.py                  # disposable inboxes
    python attacks/round4_account_farm.py --clean-emails   # real-looking domains: the blocklist is beaten

The second variant is the lesson: the blocklist is evaded, the velocity and the device cluster are not.
"""

import argparse
import random

from _common import LabClient, browser_headers, report, world_pool

DISPOSABLE = ["mailinator.com", "guerrillamail.com", "10minutemail.com", "trashmail.com", "yopmail.com"]
CLEAN = ["mail.example", "webmail.example", "inbox.example"]
DEVICES = 3


def run(count=20, clean_emails=False):
    actor = "bot:farm_clean" if clean_emails else "bot:farm"
    box = world_pool("cloud_vm")[6 if clean_emails else 5]       # one rented host per farm
    rng = random.Random(4)
    headers = browser_headers("link", accept_json=True)
    tally = {"created": 0, "stopped": 0}
    for i in range(count):
        farm = LabClient(actor, ip=box)
        farm.set_cookie("did", f"{actor.split(':')[1]}-profile-{i % DEVICES}")
        email = f"farm_{rng.randint(10000, 99999)}@{rng.choice(CLEAN if clean_emails else DISPOSABLE)}"
        r = farm.post("/api/register", json={"email": email, "password": "P@ssw0rd-farm-1", "name": "Pat Farmer"}, headers=headers)
        tally["created" if r.status_code == 201 else "stopped"] += 1
    return {"attacker": actor, "attempted": count, "succeeded": tally["created"], "accounts_created": tally["created"],
            "stopped": tally["stopped"], "clean_emails": clean_emails}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--clean-emails", action="store_true")
    a = ap.parse_args()
    out = run(a.count, a.clean_emails)
    print(f"[farm] {out['attempted']} registrations ({'clean' if a.clean_emails else 'disposable'} emails) -> "
          f"{out['accounts_created']} accounts created, {out['stopped']} stopped")
    report(**out)
