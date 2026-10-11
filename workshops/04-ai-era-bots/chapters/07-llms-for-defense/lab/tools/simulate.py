"""
W4 Chapter 7 — Drop-day traffic: simulated real users (+ the usual bots)

Generates the sessions the analyst triages and the real users every
checkpoint measures false positives on. Six human cohorts, each chosen
because it breaks a naive rule somewhere:

  desktop          the "typical" shopper; ~15% sit behind corporate egress
  mobile_cgnat     phones on carrier CGNAT: many people per IP
  power_user       sneakerheads who know the drop: fast, few pages
  vpn              commercial VPN: a hosting ASN, Firefox on Linux is common.
                   Round 2's bait bot exits from the SAME pool.
  privacy_browser  Firefox resistFingerprinting / Brave: generic
                   Accept-Language, often Firefox on Linux
  keyboard_only    screen-reader and keyboard users: slow, few pages

Logins: some users log into long-standing accounts. Those are the only
"verified humans" the gate gets (defenses/gate.py), and they are NOT a
random sample: privacy-browser and VPN users log in less.

Run (the demo site must be up):
    python tools/simulate.py                 # 600 users + baseline bots
    python tools/simulate.py --no-bots       # real users only
    python tools/simulate.py --humans 200 --seed 7
"""

import argparse
import importlib.util
import os
import random
from collections import Counter

import labclient as labnet
import shopper
from shopper import UA, Persona, browser_headers, human_think, pick_locale

ATTACKS_DIR = os.path.join(os.path.dirname(__file__), "..", "attacks")

COHORTS = {"desktop": 0.40, "mobile_cgnat": 0.25, "power_user": 0.10,
           "vpn": 0.10, "privacy_browser": 0.08, "keyboard_only": 0.07}
# P(logs in), P(account is long-standing | logs in)
LOGIN = {"desktop": (0.6, 0.7), "mobile_cgnat": (0.5, 0.7), "power_user": (0.8, 0.9),
         "vpn": (0.5, 0.6), "privacy_browser": (0.35, 0.6), "keyboard_only": (0.5, 0.7)}
LOYAL_ACCOUNTS = [f"user{i:04d}" for i in range(400) if i % 3 != 2]
NEW_ACCOUNTS = [f"user{i:04d}" for i in range(400) if i % 3 == 2]


def pick_account(rng, cohort):
    p_login, p_loyal = LOGIN[cohort]
    if rng.random() >= p_login:
        return None
    return rng.choice(LOYAL_ACCOUNTS if rng.random() < p_loyal else NEW_ACCOUNTS)


def human_persona(rng, cohort):
    mobile = cohort == "mobile_cgnat"
    locale = pick_locale(rng, countries=("ES", "US", "DE") if mobile else None)
    ua_key = rng.choice(shopper.MOBILE_UAS if mobile else shopper.DESKTOP_UAS)
    think, browse = human_think(6.0), rng.randint(1, 5)

    if mobile:
        ip, _ = labnet.Pool("mobile", country=locale[2], rng=rng).next()
        browse = rng.randint(1, 4)
    elif cohort == "vpn":
        ip, _ = labnet.Pool("vpn", rng=rng).next()
        if rng.random() < 0.4:
            ua_key = "firefox_linux"
    elif cohort == "desktop" and rng.random() < 0.15:
        locale = pick_locale(rng, countries=("US",))
        ip, _ = labnet.Pool("corporate", rng=rng).next()
    else:
        ip, _ = labnet.Pool("residential", country=locale[2], rng=rng).next()

    headers = browser_headers(locale[1])
    if cohort == "power_user":
        think, browse = human_think(2.0), rng.randint(0, 1)
    elif cohort == "keyboard_only":
        think = human_think(9.0)
    elif cohort == "privacy_browser":
        # resistFingerprinting / Brave: generic language, often Firefox on Linux
        ua_key = "firefox_linux" if rng.random() < 0.5 else rng.choice(["firefox_win", "chrome_win"])
        headers = browser_headers(["en-US", "en"])

    return Persona(actor="human", cohort=cohort, is_bot=False, ip=ip, user_agent=UA[ua_key],
                   headers=headers, think=think, browse=browse, account=pick_account(rng, cohort))


def legit_personas(n, seed):
    rng = random.Random(seed)
    cohorts = rng.choices(list(COHORTS), weights=list(COHORTS.values()), k=n)
    return [human_persona(rng, c) for c in cohorts]


def load_attack(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ATTACKS_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def drop_day(humans=600, bots=True, seed=1):
    """A normal drop day: real users interleaved with the baseline bots."""
    personas = legit_personas(humans, seed)
    if bots:
        personas += load_attack("round0_baseline").personas(seed=seed)
    random.Random(seed).shuffle(personas)
    return shopper.run_sessions(personas, seed=seed, run=f"simulate-{seed}")


def main():
    parser = argparse.ArgumentParser(description="Generate drop-day traffic.")
    parser.add_argument("--humans", type=int, default=600)
    parser.add_argument("--no-bots", action="store_true")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    print(f"=== Drop day: {args.humans} real users"
          f"{'' if args.no_bots else ' + baseline bots'} → {labnet.target()} ===")
    results = drop_day(args.humans, not args.no_bots, args.seed)
    by = Counter((r["actor"], r["cohort"], r["final"]) for r in results)
    for (actor, cohort, final), n in sorted(by.items(), key=str):
        print(f"  {actor:<16} {cohort:<16} {str(final):<12} {n}")
    print(f"\n{len(results)} sessions tagged run=simulate-{args.seed}. "
          f"Ground truth appended to data/truth.jsonl")


if __name__ == "__main__":
    main()
