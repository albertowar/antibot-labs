"""
The legitimate-user population, one week at a time (inherited from W2 Ch8)

200 simulated customers log in every week, generated from a fixed seed per
week so every checkpoint sees the same people. Most are unremarkable
browsers on home broadband. The minorities matter, because each one trips
exactly the kind of weak signal a layer was tuned on:

    persona        share   trips                        why it is a real person
    vpn            ~6%     datacenter_asn, tz mismatch  privacy, work VPN, travel
    cgnat          ~5%     ip_elevated / ip_burst       mobile carrier NAT
    privacy        ~3%     fp_randomized                Firefox RFP, Brave, extensions
    tor            ~1%     tor_exit + fp_randomized     Tor Browser
    a11y           ~2%     no_pointer                   keyboard-only, screen readers
    autofill       ~10%    no_keystrokes                password managers, paste
    old_device     ~2%     outdated_browser             can't upgrade the hardware
    typo           ~8%     (a failed login)             people mistype passwords

New in W3 Ch4, the world moves under the stack (tools/weeks.py):

    week 3+  Chrome 146 ships: new header order, new JA4 (labclient.py)
    week 3+  the mobile share doubles (a marketing push)
    week 3+  Example Fiber bought 203.0.113.0/26 from Example Cloud; 40% of
             fiber customers now connect from it. The edge's snapshot still
             says "datacenter", and the first /29 is still on the community
             blocklist (world.json). Real people, blocked by stale data.

And the known-good cohort: ten synthetic monitors (persona `monitor`) that
sign in twice a week with the X-Known-Good token. They are scored like
everyone else and never enforced against (defenses/allowlist.py); the
signals that fire on them are the live false-positive rate.

Run by itself:
    python tools/population.py --week 1     # 200 customers + monitors, prints per-persona outcomes
"""

import argparse
import os
import random
from collections import Counter, defaultdict

import labclient
from labclient import (BROWSERS, LabSession, browser_headers, fingerprint, human_path, ip_from,
                       ip_in, ja4_for, keystrokes, pool_tz, taps)

SEED = 2026
SIZE = 200
WEEK_SECONDS = 7 * 86400
DEVICES = [("chrome-win", 36), ("chrome-mac", 10), ("safari-mac", 8), ("firefox-win", 8),
           ("firefox-linux", 3), ("safari-ios", 20), ("chrome-android", 15)]
HOME_POOLS = [("isp-a", 35), ("isp-b", 25), ("fiber", 20), ("dsl", 20)]

MOBILE_PUSH_WEEK = 3
REASSIGN_WEEK, REASSIGNED_RANGE, REASSIGNED_SHARE = 3, "203.0.113.0/26", 0.4

MONITORS = [("chrome-win", "isp-a"), ("chrome-win", "isp-a"), ("chrome-win", "fiber"), ("chrome-win", "isp-b"),
            ("chrome-mac", "isp-a"), ("firefox-linux", "dsl"), ("safari-ios", "isp-a"), ("safari-ios", "fiber"),
            ("chrome-android", "isp-a"), ("chrome-android", "isp-b")]
KNOWN_GOOD = {"X-Known-Good": os.environ.get("KNOWN_GOOD_TOKEN", "lab-monitor-7f3a")}


def _weighted(rng, items):
    return rng.choices([i for i, _ in items], weights=[w for _, w in items])[0]


def week_start(week):
    return week * WEEK_SECONDS


def make_people(week=1, size=SIZE, seed=SEED):
    rng = random.Random(seed * 100 + week)
    devices = list(DEVICES)
    if week >= MOBILE_PUSH_WEEK:
        devices = [(d, w * 2 if BROWSERS[d]["mobile"] else w) for d, w in devices]
    next_ip = Counter()
    people = []
    for i in range(size):
        device = _weighted(rng, devices)
        home = _weighted(rng, HOME_POOLS)
        traits = []
        if rng.random() < 0.02 and not BROWSERS[device]["mobile"]:
            device = "chrome-win7"
            traits.append("old_device")
        if rng.random() < 0.01:
            device, traits = "firefox-win", traits + ["tor"]
        elif rng.random() < 0.03:
            traits.append("privacy")
        if BROWSERS[device]["mobile"] and rng.random() < 0.15:
            traits.append("cgnat")
        elif not BROWSERS[device]["mobile"] and "tor" not in traits and rng.random() < 0.06:
            traits.append("vpn")
        if not BROWSERS[device]["mobile"] and rng.random() < 0.02:
            traits.append("a11y")
        if rng.random() < 0.10:
            traits.append("autofill")
        if rng.random() < 0.08:
            traits.append("typo")

        if "tor" in traits:
            pool = "tor"
        elif "vpn" in traits:
            pool = "vpn"
        elif "cgnat" in traits:
            pool = "mobile"
        else:
            pool = home
        # VPN and Tor exits are shared by many users; homes are not
        index = next_ip[pool] if pool not in ("vpn", "tor") else rng.randrange(8)
        next_ip[pool] += 1
        ip = ip_from(pool, index)
        if pool == "fiber" and week >= REASSIGN_WEEK and rng.random() < REASSIGNED_SHARE:
            ip = ip_in(REASSIGNED_RANGE, next_ip["reassigned"])   # the first 8 are "blocklisted"
            next_ip["reassigned"] += 1
            traits.append("new_range")
        spanish = rng.random() < 0.08
        people.append({
            "id": i, "persona": "+".join(t for t in traits if t != "new_range") or "typical",
            "traits": traits, "device": device, "pool": pool, "ip": ip,
            "home_tz": "UTC" if "tor" in traits else pool_tz(home),
            "languages": ["es-US", "es", "en"] if spanish else ["en-US", "en"],
            "accept_language": "es-US,es;q=0.9,en;q=0.8" if spanish else "en-US,en;q=0.9",
            "seed": seed * 10_000 + week * 1000 + i,
            "clock": week_start(week) + rng.randrange(WEEK_SECONDS),
            "known_good": False,
        })
    return people


def make_monitors(week=1, seed=SEED):
    """Ten monitors, each checking twice a week at fixed times."""
    people = []
    for j, (device, pool) in enumerate(MONITORS):
        ip = ip_from(pool, 100 + j)
        if pool == "fiber" and week >= REASSIGN_WEEK:
            ip = ip_in(REASSIGNED_RANGE, 3 if j == 2 else 40)   # one lands in the blocklisted /29
        for check in range(2):
            people.append({
                "id": 250 + j, "persona": "monitor", "traits": [], "device": device, "pool": pool,
                "ip": ip, "home_tz": pool_tz(pool), "languages": ["en-US", "en"],
                "accept_language": "en-US,en;q=0.9", "seed": seed * 50_000 + week * 100 + j * 2 + check,
                "clock": week_start(week) + (2 + check * 3) * 86400 + 3600 * (9 + j), "known_good": True,
            })
    return people


def visit(person, week=1):
    """One real customer signing in. Returns (outcome, session)."""
    rng = random.Random(person["seed"])
    b = BROWSERS[person["device"]]
    session = LabSession(f"human:{person['persona']}", person["ip"],
                         ja4_for(b["engine"], week, person["device"]),
                         browser_headers(person["device"], person["accept_language"], week),
                         week=week, clock=person["clock"], extra=KNOWN_GOOD if person["known_good"] else None)
    session.open_login()
    traits = person["traits"]
    user, password = labclient.users.username(person["id"]), labclient.users.password(person["id"])
    if "typo" in traits:
        password = password[:-1] + "0"
    if "a11y" in traits:
        mouse, pointer = [], "mouse"
    elif b["mobile"]:
        mouse, pointer = taps(rng), "touch"
    else:
        mouse, pointer = human_path(rng), "mouse"
    keys = [] if "autofill" in traits else keystrokes(rng, len(user) + len(password))
    fp = fingerprint(rng, person["device"], person["home_tz"], person["languages"],
                     randomized=bool({"privacy", "tor"} & set(traits)))
    session.send_telemetry(fp, mouse, keys, pointer)
    outcome, _ = session.login(user, password)
    return outcome, session


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send one week's customers through the login")
    parser.add_argument("--week", type=int, default=1)
    args = parser.parse_args()
    people = sorted(make_people(args.week) + make_monitors(args.week), key=lambda p: p["clock"])
    by_persona = defaultdict(Counter)
    for person in people:
        outcome, _ = visit(person, args.week)
        by_persona[person["persona"]][outcome] += 1
    print(f"=== week {args.week}: {len(people)} simulated customers (what each one experienced) ===")
    for persona, outcomes in sorted(by_persona.items(), key=lambda kv: -sum(kv[1].values())):
        print(f"  {persona:<22} {sum(outcomes.values()):>4}   " +
              ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items())))
    print("\n  'invalid' for a typo is correct. 'invalid' for anyone else is a deceptive")
    print("  block: the customer thinks they mistyped. Count those as blocked.")
