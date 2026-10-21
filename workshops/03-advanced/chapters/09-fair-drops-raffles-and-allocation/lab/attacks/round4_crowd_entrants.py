"""
Round 4 attack: a crowd of paid people (the residual no allocation rule removes).

The crew gives up on accounts it owns. It pays twenty-four real people a small fee to enter with THEIR account,
THEIR card and THEIR address, from THEIR home connection, one by one, and buys the pair from each winner
afterwards, off the site. Nothing here is automated abuse of the entry form: each entry is a genuine, once-only
entry by a genuine person with a genuine history. What is not genuine is the intent, and no check in this lab can
read intent.

    python attacks/round4_crowd_entrants.py                # enter
    python attacks/round4_crowd_entrants.py --claim        # the winners pay and take delivery at home

This is written as a script only so the lab can count its wins next to everyone else's: it drives the same
public routes, at a human pace. The thing to take from it is the number it wins in Round 4: roughly its share of
the entries. Limits that bind the PAIR to the person (identity checks at delivery, a ban on resale, a per-person
cap enforced over time) are policy and operations, not a draw.
"""

import argparse
import random
import time

from _common import args_claim, claim, enter, fleet, login, map_threads, only_wins, person_ja4, report, world_pool
from demo_site.ext import raffle_world as W

ACTOR = "bot:crowd"


def run(kit):
    homes = world_pool("home_eu")
    rng = random.Random(11)
    tally = {"entered": 0, "refused": 0, "stopped": 0}

    def one(a):
        time.sleep(rng.uniform(0.0, 3.0))
        c = fleet(f"{ACTOR}:{a.n:03d}", ip=homes[a.n], ja4=person_ja4(a.email))
        if not login(c, a.email, a.password):
            tally["stopped"] += 1
            return
        code, _ = enter(c, {})
        tally["entered" if code == 201 else "refused"] += 1
    map_threads(one, kit, workers=8)
    return {"attacker": ACTOR, "attempted": len(kit), "succeeded": tally["entered"], **tally}


def run_claim(kit, wins=None):
    homes = world_pool("home_eu")
    out = {"paid": 0, "held": 0, "lost": 0, "refused": 0}

    def one(a):
        c = fleet(f"{ACTOR}:{a.n:03d}", ip=homes[a.n], ja4=person_ja4(a.email))
        if not login(c, a.email, a.password):
            out["refused"] += 1
            return
        out[claim(c, a.email, {})] += 1
    map_threads(one, only_wins(kit, wins), workers=8)
    return {"attacker": ACTOR, "attempted": len(kit), "succeeded": out["paid"], "claims": out}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    args_claim(ap)
    a = ap.parse_args()
    kit = W.kit("crowd")
    out = run_claim(kit, a.wins) if a.claim else run(kit)
    print(f"[crowd] {out.get('claims') or {k: out[k] for k in ('entered', 'refused', 'stopped')}}")
    report(**out)
