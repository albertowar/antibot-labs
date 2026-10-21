"""
Round 0 attack: sixty patient accounts against a first-come, first-served drop.

The economy: the pair resells for a multiple of its price, so a reseller wants every unit and will pay for
accounts. Chapter 4's funnel (Round 0's defense) already took away the cheap tricks: skip the page and you are
blocked, buy faster than a person can click and you are blocked, buy twice from one device and you are blocked.
This crew does what the funnel cannot punish:

  - it STAGES before the drop opens: register sixty accounts, one device cookie each (the cap counts devices),
    view the drop page, then wait;
  - at the opening second every account buys at once, a second or more after its view, so the funnel sees a
    patient visitor. One pair per account passes `max_per_account` too.

    python attacks/round0_patient_farm.py                  # first come, first served: sixty buys at the opening second

At level 1 and up the store refuses this crew's route (it answers 409 raffle_only): patient_farm has no raffle
mode, which is Round 1's point. Chapter 4's `scalper` and this one differ in the thing that matters: accounts.
"""

import argparse
import time

from _common import PATIENCE_S, SKU, buy, fleet, headers, map_threads, mode, open_epoch, register, report
from demo_site.ext import raffle_world as W

ACTOR = "bot:patient_farm"


def run(accounts=60):
    m, info = mode()
    opens = open_epoch(info)
    tally = {"purchased": 0, "sold_out": 0, "stopped": 0}
    staged = []

    def stage(i):                                      # before the opening second: register, one device each, view the drop
        email, pw, _ = W.farm_account("patient_farm", i)
        c = fleet(f"{ACTOR}:{i:03d}")
        if not register(c, email, pw, verify=False):
            tally["stopped"] += 1
            return
        c.get(f"/api/products/{SKU}", headers=headers("link"))          # the funnel's first step
        staged.append((c, email))

    def go(item):
        c, email = item
        code = buy(c, email)
        tally["purchased" if code == 201 else "sold_out" if code == 410 else "stopped"] += 1
    map_threads(stage, range(accounts), workers=16)
    time.sleep(max(0.0, opens - time.time(), PATIENCE_S))              # all of them are patient: past the funnel's floor
    map_threads(go, staged, workers=max(1, len(staged)))
    return {"attacker": ACTOR, "attempted": accounts, "succeeded": tally["purchased"], "mode": m, **tally}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--accounts", type=int, default=60)
    a = ap.parse_args()
    out = run(a.accounts)
    print(f"[patient_farm] {out['attempted']} staged accounts -> {out['purchased']} pairs bought, "
          f"{out['sold_out']} sold out, {out['stopped']} stopped (mode {out['mode']})")
    report(**out)
