"""
Round 1 attack: two hundred fresh accounts, and the numbers contest a raffle leaves open.

A raffle removes speed from the contest (nobody wins by being first), but it still counts tickets. This crew
fields 200 accounts it registers on the spot: a mailbox on a catch-all domain, a virtual card from one BIN per
account, one drop address for every pair. Each account enters, and tries to enter two more times (a naive crew
does not know the rule is one per account).

    python attacks/round1_account_farm.py                  # enter (a raffle) or stage and buy (first come)
    python attacks/round1_account_farm.py --claim          # after the draw: pay for the pairs the accounts won
    python attacks/round1_account_farm.py --accounts 120

It reads the drop the way a visitor does, so the same script is the "before" at level 0: against a first-come
sale it stages (register, view, wait for the opening second) and buys, like Round 0's farm with 200 accounts.
"""

import argparse
import time

from _common import (PATIENCE_S, SKU, args_claim, buy, claim, enter, fleet, headers, login, map_threads, mode,
                     only_wins, open_epoch, register, report)
from demo_site.ext import raffle_world as W

ACTOR = "bot:account_farm"
TRIES = 2


def _shipping(i):
    line1, city, post = W.DROP_ADDRESS
    return {"line1": line1, "city": city, "postcode": post}


def run(accounts=200):
    m, info = mode()
    opens = open_epoch(info)
    tally = {"entered": 0, "refused": 0, "purchased": 0, "stopped": 0}
    reasons = {}
    staged = []

    def one(i):
        email, pw, card = W.farm_account("account_farm", i)
        c = fleet(f"{ACTOR}:{i:03d}")
        if not register(c, email, pw, verify=m == "raffle"):
            tally["stopped"] += 1
            return
        if m == "first_come":                          # stage: view the drop now, buy at the opening second
            c.get(f"/api/products/{SKU}", headers=headers("link"))
            staged.append((c, email))
            return
        for _ in range(TRIES):
            code, signals = enter(c, dict(_shipping(i), card=card))
            if code == 201:
                tally["entered"] += 1
            else:
                tally["refused"] += 1
                reasons[signals or str(code)] = reasons.get(signals or str(code), 0) + 1
    map_threads(one, range(accounts), workers=16)
    if m == "first_come":
        time.sleep(max(0.0, opens - time.time(), PATIENCE_S))

        def go(item):
            tally["purchased" if buy(item[0], item[1]) == 201 else "stopped"] += 1
        map_threads(go, staged, workers=max(1, len(staged)))
    won = tally["purchased"] if m == "first_come" else tally["entered"]
    return {"attacker": ACTOR, "attempted": accounts, "succeeded": won, "mode": m, **tally, "refused_for": reasons}


def run_claim(accounts=200, wins=None):
    out = {"paid": 0, "held": 0, "lost": 0, "refused": 0}

    def one(i):
        email, pw, card = W.farm_account("account_farm", i)
        c = fleet(f"{ACTOR}:{i:03d}")
        if not login(c, email, pw):
            out["refused"] += 1
            return
        out[claim(c, email, dict(_shipping(i), card=card))] += 1
    map_threads(one, only_wins(range(accounts), wins, key=lambda i: W.farm_account("account_farm", i)[0]), workers=16)
    return {"attacker": ACTOR, "attempted": accounts, "succeeded": out["paid"], "claims": out}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--accounts", type=int, default=200)
    args_claim(ap)
    a = ap.parse_args()
    out = run_claim(a.accounts, a.wins) if a.claim else run(a.accounts)
    if a.claim:
        print(f"[account_farm] claims: {out['claims']}")
    else:
        print(f"[account_farm] {out['attempted']} accounts, mode {out['mode']}: {out['entered']} entries accepted, "
              f"{out['refused']} refused, {out['purchased']} pairs bought")
    report(**out)
