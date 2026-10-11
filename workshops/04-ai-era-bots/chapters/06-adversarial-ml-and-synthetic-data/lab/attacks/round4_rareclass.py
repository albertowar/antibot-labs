"""
W4 Ch6 — Round 4 Attack: the rare class the model never learned (Section 6.6)

Every defense so far assumed the model had seen enough of each kind of bot
to draw a boundary. This attack exploits the opposite: a NEW family the
labelled data barely contains.

The family is a "slow mobile reseller": real-device iPhone/Android
fingerprints (bought, internally consistent), residential/mobile exits,
patient human-like pacing, and — the point — it almost never hits a
honeypot and never logs in. So almost none of these sessions get a label.
The honeypot-fed bot class is full of cloud scrapers; this family sits in a
corner of feature space with maybe a handful of labelled examples. A
supervised model has nothing to learn the corner from, so it waves them
through. This is class imbalance, not evasion: the attacker changed nothing
clever, they simply live where your labels are thin.

  - vs model v4 (DEFENSE_LEVEL=4, stub augment.py)      → the family gets through
  - vs model v5 (SMOTE-augmented minority, augment.py)  → the corner is filled in
    and recall on the family jumps — at an honest false-positive cost on the
    real mobile users who live nearby.

Run (demo site up at DEFENSE_LEVEL=4):
    python attacks/round4_rareclass.py
"""

import argparse
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import advlib  # noqa: E402
import labnet  # noqa: E402
import shopper  # noqa: E402
from shopper import (UA, Persona, browser_headers, fingerprint, human_think,  # noqa: E402
                     mobile_behavior, pick_device, pick_locale)

# A few of the family blunder into the honeypot: those are the only labels
# the defender ever gets for this corner. Keep it small on purpose.
HONEYPOT_P = 0.05


def reseller(rng):
    """A patient mobile reseller on a real device and a carrier/residential exit."""
    device = pick_device(rng, mobile=True)
    ua_key = shopper.DEVICES[device][6][0]
    locale = pick_locale(rng, countries=("ES", "US", "DE"))
    fp = fingerprint(rng, device, locale, ua_key)
    kind = rng.choice(["mobile", "residential"])
    pool = labnet.Pool(kind, country=locale[2], rng=rng)
    ip, _ = pool.next()
    return Persona(actor="round4_rareclass", cohort="reseller", is_bot=True, ip=ip,
                   user_agent=UA[ua_key], headers=browser_headers(locale[1]), fp=fp,
                   behavior=mobile_behavior(rng), think=human_think(8.0),
                   browse=rng.randint(1, 3), honeypot=HONEYPOT_P, usd_per_gb=pool.usd_per_gb)


def personas(n=40, seed=0):
    rng = random.Random(seed + 4000)
    return [reseller(rng) for _ in range(n)]


def run(n=40, seed=94, quiet=False):
    out = sys.stdout
    if quiet:
        sys.stdout = open(os.devnull, "w")
    try:
        results = shopper.run_sessions(personas(n, seed), seed=seed, run="round4_rareclass")
    finally:
        if quiet:
            sys.stdout.close()
            sys.stdout = out
    run.stats = {"ok": sum(shopper.succeeded(r) for r in results), "n": len(results),
                 "usd": sum(r["usd"] for r in results)}
    return results


def main():
    parser = argparse.ArgumentParser(description="The rare, barely-labelled bot family.")
    parser.add_argument("--n", type=int, default=60)
    parser.add_argument("--seed", type=int, default=94)
    args = parser.parse_args()
    print(f"=== Round 4: the slow mobile reseller → {labnet.target()} ===")
    results = run(n=args.n, seed=args.seed)
    s = run.stats
    print(f"\n  {s['ok']}/{s['n']} checkouts confirmed  (≈ ${s['usd']:.2f} simulated)")
    print("  The family lives where the labels are thin. Augment the minority to fill it in.")


if __name__ == "__main__":
    main()
