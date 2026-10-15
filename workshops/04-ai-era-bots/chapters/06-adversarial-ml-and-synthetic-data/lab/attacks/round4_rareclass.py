"""
Round 4 attack: the rare class the model never learned

Every defense so far assumed the model had seen enough of each kind of bot to draw a boundary. This attack
exploits the opposite: a NEW family the labelled data barely contains.

The family is a "slow mobile reseller": real-device iPhone/Android fingerprints (bought, internally
consistent), residential-proxy exits, patient human-like pacing, and, the point, it almost never hits a
honeypot and never signs in. So almost none of these sessions get a label. The honeypot-fed bot class is full
of cloud scrapers; this family sits in a corner of feature space with a handful of labelled examples at best.
A supervised model has nothing to learn the corner from, so it waves them through. This is class imbalance,
not evasion: the attacker changed nothing clever, they simply live where your labels are thin.

  - vs model v4 (DEFENSE_LEVEL=3)  -> the family gets through
  - vs model v5 (SMOTE-augmented minority, DEFENSE_LEVEL=4) -> the corner is filled in and recall on the family
    jumps, at an honest false-positive cost on the real mobile users who live nearby

Run (store up):
    python tools/simulate.py --wave round4_rareclass      # the wave the defender trains on
    python attacks/round4_rareclass.py                    # the same family, sent live
"""

import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))

import labclient  # noqa: E402  (runs the labnet guard)
import shopper  # noqa: E402
from shopper import (UA, Persona, accept_language, fingerprint, human_think,  # noqa: E402
                     mobile_behavior, pick_device, pick_locale)

HISTORY_N, HISTORY_SEED = 60, 94
# A few of the family blunder into the honeypot: those are the only labels the defender ever gets for
# this corner. Keep it small on purpose.
HONEYPOT_P = 0.05


def reseller(rng, n):
    """A patient mobile reseller on a real phone and a residential-proxy exit."""
    device = pick_device(rng, mobile=True)
    ua_key = shopper.DEVICES[device][6][0]
    locale = pick_locale(rng, countries=("US",))
    return Persona(actor=f"bot:reseller:{n:03d}", persona="reseller", browser=("reseller",),
                   ip=rng.choice(labclient.world_pool("resi_us")), ua=UA[ua_key],
                   accept_language=accept_language(locale[1]), fp=fingerprint(rng, device, locale, ua_key),
                   behavior=mobile_behavior(rng), think=human_think(8.0), browse=rng.randint(1, 3),
                   honeypot=HONEYPOT_P, usd_per_gb=4.0)


def personas(n=40, seed=0):
    rng = random.Random(seed + 4000)
    return [reseller(rng, i) for i in range(n)]


def run(n=HISTORY_N, seed=HISTORY_SEED):
    return shopper.run_sessions(personas(n, seed), seed=seed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="The rare, barely-labelled bot family.")
    parser.add_argument("--n", type=int, default=40)
    parser.add_argument("--seed", type=int, default=HISTORY_SEED)
    args = parser.parse_args()
    print(f"=== Round 4: the slow mobile reseller -> {labclient.BASE_URL} ===")
    results = run(args.n, args.seed)
    ok = sum(shopper.succeeded(r) for r in results)
    print(f"\n  {ok}/{len(results)} purchases confirmed  (~${sum(r['usd'] for r in results):.2f} simulated)")
    print("  The family lives where the labels are thin. Augment the minority to fill it in.")
    print(json.dumps(shopper.summarize_attack(results)))
