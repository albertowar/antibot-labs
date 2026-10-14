"""
Round 2 attack: a scalper sweeping the limited drop.

The economy: capture scarce stock and resell it. The scalper does not look like a bot to a rate limit
(it buys, from a rotating pool of hosting addresses, a handful of requests per identity); what it cannot
hide is HOW it buys. Three variants, each beating the defense that stopped the one before:

    python attacks/round2_scalper.py               # machine speed: view the drop, buy in the same breath
    python attacks/round2_scalper.py --skip-view   # skip the funnel: POST the buy without ever viewing the drop
    python attacks/round2_scalper.py --patient     # wait out the speed floor, spread over 4 device cookies

80 attempts, each a fresh session (a stand-in for an account) on one of four device cookies. The buy is
POST /api/buy {sku, size, email}, the call the site's own JavaScript makes.
"""

import argparse
import time

from _common import LabClient, browser_headers, map_threads, report, world_pool

SKU, SIZE = "lab-runner-9", "10"
ACTOR = "bot:scalper"
DEVICES = 4
PATIENCE_S = 1.1            # just above the funnel floor


def run(attempts=80, skip_view=False, patient=False):
    pool = world_pool("cloud_vm")
    mode = "patient" if patient else "skip-view" if skip_view else "machine-speed"
    headers = browser_headers("link", accept_json=True)
    tally = {"purchased": 0, "stopped": 0, "sold_out": 0}

    def attempt(i):
        bot = LabClient(ACTOR, pool=pool)
        bot.set_cookie("did", f"scalp-{mode}-dev-{i % DEVICES}")
        if not skip_view:
            bot.get(f"/api/products/{SKU}", headers=headers)
        if patient:
            time.sleep(PATIENCE_S)
        r = bot.post("/api/buy", json={"sku": SKU, "size": SIZE, "email": f"scalp{i}@example.test"}, headers=headers)
        key = "purchased" if r.status_code == 201 else "sold_out" if r.status_code == 410 else "stopped"
        tally[key] += 1
    map_threads(attempt, range(attempts))
    return {"attacker": ACTOR, "attempted": attempts, "succeeded": tally["purchased"], "pairs_won": tally["purchased"],
            "stopped": tally["stopped"], "sold_out": tally["sold_out"], "devices": DEVICES, "mode": mode}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--attempts", type=int, default=80)
    ap.add_argument("--skip-view", action="store_true")
    ap.add_argument("--patient", action="store_true")
    a = ap.parse_args()
    out = run(a.attempts, a.skip_view, a.patient)
    mode = out["mode"]
    print(f"[scalper:{mode}] {out['attempted']} attempts -> {out['pairs_won']} pairs won, {out['stopped']} stopped, {out['sold_out']} sold out")
    report(**out)
