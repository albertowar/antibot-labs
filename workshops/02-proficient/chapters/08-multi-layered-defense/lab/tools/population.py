"""
Chapter 8: The legitimate-user population (the other half of every round)

200 simulated customers log in to the demo store, generated from a fixed
seed so every checkpoint sees the same people. Most of them are unremarkable
browsers on home broadband. The ones who matter are the minorities, because
each one trips exactly the kind of weak signal that a layer was tuned on:

    persona        share   trips                        why it is a real person
    vpn            ~6%     datacenter_asn, tz mismatch  privacy, work VPN, travel
    cgnat          ~5%     ip_elevated / ip_burst       mobile carrier NAT
    privacy        ~3%     fp_randomized                Firefox RFP, Brave, extensions
    tor            ~1%     tor_exit + fp_randomized     Tor Browser
    a11y           ~2%     no_pointer                   keyboard-only, screen readers
    autofill       ~10%    no_keystrokes                password managers, paste
    old_device     ~2%     outdated_browser             can't upgrade the hardware
    typo           ~8%     (a failed login)             people mistype passwords

Traits are drawn independently, so some people carry two. Real users always
complete challenges: they solve the proof-of-work (their browser does) and
they read their own email for a step-up code.

Run by itself:
    python tools/population.py          # all 200, prints per-persona outcomes
"""

import random
from collections import Counter, defaultdict

import labclient
from labclient import (BROWSERS, LabSession, browser_headers, fingerprint, human_path, ip_from,
                       keystrokes, pool_tz, taps)

SEED = 2026
SIZE = 200
DEVICES = [("chrome-win", 36), ("chrome-mac", 10), ("safari-mac", 8), ("firefox-win", 8),
           ("firefox-linux", 3), ("safari-ios", 20), ("chrome-android", 15)]
HOME_POOLS = [("isp-a", 35), ("isp-b", 25), ("fiber", 20), ("dsl", 20)]


def _weighted(rng, items):
    return rng.choices([i for i, _ in items], weights=[w for _, w in items])[0]


def make_people(size=SIZE, seed=SEED):
    rng = random.Random(seed)
    next_ip = Counter()
    people = []
    for i in range(size):
        device = _weighted(rng, DEVICES)
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
        spanish = rng.random() < 0.08
        people.append({
            "id": i, "persona": "+".join(traits) or "typical", "traits": traits,
            "device": device, "pool": pool, "ip": ip_from(pool, index),
            "home_tz": "UTC" if "tor" in traits else pool_tz(home),
            "languages": ["es-US", "es", "en"] if spanish else ["en-US", "en"],
            "accept_language": "es-US,es;q=0.9,en;q=0.8" if spanish else "en-US,en;q=0.9",
            "seed": seed * 10_000 + i,
        })
    return people


def visit(person):
    """One real customer signing in. Returns (outcome, session)."""
    rng = random.Random(person["seed"])
    b = BROWSERS[person["device"]]
    session = LabSession(f"human:{person['persona']}", person["ip"], labclient.JA4[b["engine"]],
                         browser_headers(person["device"], person["accept_language"]))
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
    people = make_people()
    by_persona = defaultdict(Counter)
    for person in people:
        outcome, _ = visit(person)
        by_persona[person["persona"]][outcome] += 1
    print(f"=== {len(people)} simulated customers (what each one experienced) ===")
    for persona, outcomes in sorted(by_persona.items(), key=lambda kv: -sum(kv[1].values())):
        print(f"  {persona:<22} {sum(outcomes.values()):>4}   " +
              ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items())))
    print("\n  'invalid' for a typo is correct. 'invalid' for anyone else at level 3+ is a")
    print("  deceptive block: the customer thinks they mistyped. Count those as blocked.")
