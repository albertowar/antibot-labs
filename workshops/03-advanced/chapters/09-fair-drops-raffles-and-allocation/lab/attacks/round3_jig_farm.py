"""
Round 3 attack: jigging, and then spreading out.

JIG (default). One building, eighty spellings. The crew has 80 aged accounts; every pair ships to the same
building and the entries say it differently: "3 Pier Avenue Apt 7", "3 Pier Ave #12", "3 Pier Ave., Unit 31",
five mailboxes written as eighty ("m.arlowe+9@gmail.example", "mar.lowe+40@gmail.example"), virtual cards from
one BIN. A comparison of the raw strings sees eighty different addresses and eighty different mailboxes.

    python attacks/round3_jig_farm.py                      # enter, jigged
    python attacks/round3_jig_farm.py --spread             # enter, spread out: the crew that adapts to Round 3
    python attacks/round3_jig_farm.py --claim [--spread]   # after the draw: pay for the pairs it won

SPREAD (--spread). The crew learns that sharing a spelling-family gets entries merged, and stops sharing: sixty
aged accounts created in one batch, a different mailbox domain, a different clean street address and a different
virtual card each (one BIN), entered slowly, two at a time, so there is no burst. Nothing the entries SHARE links
them except the card batch and the creation batch. The pairs that win go to a forwarding warehouse when they are
claimed (four of them), because the crew still has to collect them.
"""

import argparse
import random
import time

from _common import args_claim, claim, enter, fleet, login, map_threads, only_wins, report
from demo_site.ext import raffle_world as W


def run(kit, actor, paced):
    tally = {"entered": 0, "refused": 0, "stopped": 0}
    reasons = {}
    rng = random.Random(7)

    def one(a):
        if paced:
            time.sleep(rng.uniform(0.8, 1.4))
        c = fleet(f"{actor}:{a.n:03d}")
        if not login(c, a.email, a.password):
            tally["stopped"] += 1
            return
        code, signals = enter(c, {})
        if code == 201:
            tally["entered"] += 1
        else:
            tally["refused"] += 1
            reasons[signals or str(code)] = reasons.get(signals or str(code), 0) + 1
    map_threads(one, kit, workers=2 if paced else 16)
    return {"attacker": actor, "attempted": len(kit), "succeeded": tally["entered"], **tally, "refused_for": reasons}


def run_claim(kit, actor, forward, wins=None):
    out = {"paid": 0, "held": 0, "lost": 0, "refused": 0}
    ships = W.reshippers()

    def one(a):
        c = fleet(f"{actor}:{a.n:03d}")
        if not login(c, a.email, a.password):
            out["refused"] += 1
            return
        body = {}
        if forward:
            street, city, post = ships[a.n % len(ships)]
            body = {"line1": street, "city": city, "postcode": post}
        out[claim(c, a.email, body)] += 1
    map_threads(one, only_wins(kit, wins), workers=16)
    return {"attacker": actor, "attempted": len(kit), "succeeded": out["paid"], "claims": out}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--spread", action="store_true")
    args_claim(ap)
    a = ap.parse_args()
    crew = "spread_farm" if a.spread else "jig_farm"
    kit, actor = W.kit(crew), f"bot:{crew}"
    out = run_claim(kit, actor, forward=a.spread, wins=a.wins) if a.claim else run(kit, actor, paced=a.spread)
    print(f"[{crew}] {out.get('claims') or {k: out[k] for k in ('entered', 'refused', 'stopped')}}")
    report(**out)
