"""
Round 2 attack: a hundred bought accounts.

Round 2's trust weights make a fresh account a quarter of a ticket, so the crew stops registering and BUYS
accounts: aged, verified, with a paid order in the history. Marketplaces sell them; this lab seeds them when the
round opens (demo_site/ext/raffle_world.py, kit "aged_farm"). The crew logs each one in and enters once with the
account's saved card and saved address: every pair goes to one drop address, written the same way.

    python attacks/round2_aged_farm.py                     # enter
    python attacks/round2_aged_farm.py --claim             # after the draw: pay for the pairs the accounts won

What it shows: trust that can be bought is only a price. What beats it is the thing the accounts cannot hide,
that they all ship to one door (Round 3).
"""

import argparse

from _common import args_claim, claim, enter, fleet, login, map_threads, only_wins, report
from demo_site.ext import raffle_world as W

ACTOR = "bot:aged_farm"


def run(kit):
    tally = {"entered": 0, "refused": 0, "stopped": 0}
    reasons = {}

    def one(a):
        c = fleet(f"{ACTOR}:{a.n:03d}")
        if not login(c, a.email, a.password):
            tally["stopped"] += 1
            return
        code, signals = enter(c, {})
        if code == 201:
            tally["entered"] += 1
        else:
            tally["refused"] += 1
            reasons[signals or str(code)] = reasons.get(signals or str(code), 0) + 1
    map_threads(one, kit, workers=16)
    return {"attacker": ACTOR, "attempted": len(kit), "succeeded": tally["entered"], **tally, "refused_for": reasons}


def run_claim(kit, wins=None):
    out = {"paid": 0, "held": 0, "lost": 0, "refused": 0}

    def one(a):
        c = fleet(f"{ACTOR}:{a.n:03d}")
        if not login(c, a.email, a.password):
            out["refused"] += 1
            return
        out[claim(c, a.email, {})] += 1
    map_threads(one, only_wins(kit, wins), workers=16)
    return {"attacker": ACTOR, "attempted": len(kit), "succeeded": out["paid"], "claims": out}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    args_claim(ap)
    a = ap.parse_args()
    kit = W.kit("aged_farm")
    out = run_claim(kit, a.wins) if a.claim else run(kit)
    print(f"[aged_farm] {out.get('claims') or {k: out[k] for k in ('entered', 'refused', 'stopped')}}")
    report(**out)
