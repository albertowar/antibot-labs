"""
Round 1 attack: the distributed, one-try-per-account stuffer.

Beats per-IP velocity and per-account lockout the only way that reliably works: do not
concentrate. Each credential is tried exactly once, from a different address in a rented block
(world.json's `cloud_vm`, 60 addresses). No single IP is busy and no account sees two failures, so
neither Round 1 counter ever trips. The whole run still shares one /24 and one ASN, though, and
nearly all of what it tries are accounts that do not exist: the thread Round 2 pulls on.

Real stuffers add seconds of jitter between attempts; this one does not, so the lab runs fast.

    python attacks/round1_distributed_stuffer.py
"""

import random

from _common import LabClient, combo_list, is_success, login, map_threads, report, world_pool

ACTOR = "bot:distributed"


def run():
    pool, hits, rng = world_pool("cloud_vm"), [], random.Random(1)
    ips = [rng.choice(pool) for _ in range(1000)]

    def attempt(item):
        (email, pw), ip = item
        if is_success(login(LabClient(ACTOR, ip=ip), email, pw)):
            hits.append(email)

    pairs = combo_list()
    map_threads(attempt, list(zip(pairs, ips)))
    return {"attacker": ACTOR, "attempted": len(pairs), "succeeded": len(hits), "accounts_taken_over": len(hits),
            "addresses": len(set(ips))}


if __name__ == "__main__":
    out = run()
    print(f"[{ACTOR}] {out['attempted']} attempts from {out['addresses']} addresses -> {out['accounts_taken_over']} accounts taken over")
    report(**out)
