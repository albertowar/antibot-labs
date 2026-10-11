"""
Chapter 9 — Legitimate-traffic simulator (Section 9.7, "Measuring both sides")

Forty customers (tools/personas.py) try to buy the drop, alongside the
bots. Each simulated customer:

    1. opens the store with curl_cffi impersonating their real browser, so
       the TLS fingerprint (JA4) and headers are a real Chrome/Firefox/Safari's
    2. logs in (or registers, for the first-timer), sending login-page
       telemetry and, as the real page would at DEFENSE_LEVEL 4, solving the
       login token challenge
    3. opens the product page, waits a human dwell time, sends the page's
       fingerprint + behavior telemetry, and clicks Buy

Their fingerprints come from tools/profiles/*.json and their mouse, keyboard
and touch input from tools/humans.py. Both are synthetic. They stand in for
browsers running collector.js, which is why this script is allowed to solve
the challenge in Python: it plays the part of a real browser, not of an
attacker. Add your own capture (tools/profiles/mine.json, from /lab/capture)
and it is replayed as one more customer.

Every round's checkpoint reports what the defenses did to these people next
to what they did to the bots. A defense that challenges or blocks them is a
cost, however many bots it stops.

Run:
    python tools/legit_traffic.py            # one pass, summary per persona
"""

import hashlib
import itertools
import json
import os
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from curl_cffi import requests as cffi

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import humans  # noqa: E402
import personas  # noqa: E402
from lab import BASE_URL, ensure_local  # noqa: E402

PROFILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")
DROP = "/drop/lab-runner-9"
DWELL_S = {"mouse": (2.0, 4.5), "touch": (2.5, 5.0), "keyboard": (3.5, 6.0), "fast": (1.2, 1.6)}
IMPERSONATE_PINS = {"chrome": "chrome150", "firefox": "firefox147", "safari": "safari260",
                    "safari_ios": "safari260_ios"}
_run_counter = itertools.count()
_lock = threading.Lock()


def load_profile(name):
    with open(os.path.join(PROFILES_DIR, f"{name}.json")) as f:
        profile = json.load(f)
    profile["impersonate"] = IMPERSONATE_PINS.get(profile.get("impersonate", "chrome"),
                                                  profile.get("impersonate", "chrome"))
    return profile


def leading_zero_bits(digest):
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


def solve_challenge(nonce, fp_hash, difficulty):
    for counter in itertools.count():
        digest = hashlib.sha256(f"{nonce}:{fp_hash}:{counter}".encode()).digest()
        if leading_zero_bits(digest) >= difficulty:
            return counter


def build_fp(profile, user_rng, session_rng):
    fp = json.loads(json.dumps(profile["fp"]))
    variants = profile.get("variants", {})
    if "screen" in variants:
        fp["screen"], fp["win"] = user_rng.choice(variants["screen"])
    if "hc" in variants:
        fp["hc"] = user_rng.choice(variants["hc"])
    if "tz" in variants:
        fp["tz"] = user_rng.choice(variants["tz"])
    if "gpu" in variants:
        vendor, renderer, canvas = user_rng.choice(variants["gpu"])
        fp["webgl"], fp["canvas"] = {"vendor": vendor, "renderer": renderer}, canvas
    farble = profile.get("farble", [])
    if "canvas" in farble:
        fp["canvas"] = f"{session_rng.getrandbits(32):08x}"
    if "hc" in farble:
        fp["hc"] = session_rng.choice([2, 4, 6, 8])
    if "plugins" in farble:
        fp["plugins"] = session_rng.randint(3, 5)
    fp.update({"webdriver": False, "automation_globals": []})
    fp["worker"] = {"ua": fp["ua"], "platform": fp["platform"], "hc": fp["hc"], "languages": fp["languages"]}
    return fp


def _server_ms(response):
    timing = response.headers.get("Server-Timing", "")
    if "dur=" in timing:
        return float(timing.split("dur=")[1].split(",")[0])
    return None


def _result(user, persona, stage, response, sid=None):
    try:
        body = response.json()
    except ValueError:
        body = {"outcome": "block" if response.status_code == 403 else "error", "reasons": []}
    return {"persona": persona["name"], "email": user["email"], "stage": stage,
            "outcome": body.get("outcome", "error"), "score": body.get("score"),
            "reasons": body.get("reasons", []), "status": response.status_code,
            "score_ms": _server_ms(response), "sid": sid}


def simulate(user, persona, profile, batch=0, base_url=BASE_URL):
    """One customer's visit. Returns a result dict for the checkpoint."""
    user_rng = random.Random(user["email"])
    with _lock:
        run_no = next(_run_counter)
    session_rng = random.Random(f"{user['email']}:{time.time_ns()}:{run_no}")
    s = cffi.Session(impersonate=profile["impersonate"], verify=False, timeout=30)
    egress = persona.get("egress")
    if egress and batch:
        egress = egress.rsplit(".", 1)[0] + f".{10 + batch}"
    if not egress:
        egress = f"203.0.113.{int(hashlib.sha256(user['email'].encode()).hexdigest(), 16) % 200 + 20}"
    s.headers.update({**profile.get("headers", {}), "X-Lab-Egress": egress})
    device = (f"{session_rng.getrandbits(128):032x}" if persona.get("new_device")
              else personas.device_id(user["email"]))
    s.cookies.set("did", device, domain="localhost")
    fp = build_fp(profile, user_rng, session_rng)

    def telemetry(page, events):
        return s.post(f"{base_url}/api/telemetry", json={"page": page, "fp": fp, "events": events}).json()

    r = s.get(f"{base_url}/")
    if r.status_code == 403:
        return _result(user, persona, "page", r)
    time.sleep(session_rng.uniform(0.2, 0.6))

    if user["register"]:
        s.get(f"{base_url}/register")
        telemetry("/register", humans.typing_events(session_rng, 40))
        tag = "".join(session_rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(5))
        email = f"{session_rng.choice(personas.FIRST)}.{session_rng.choice(personas.LAST)}.{tag}@customers.example"
        r = s.post(f"{base_url}/api/register", json={
            "email": email, "password": "first-time-buyer-pw",
            "address": f"{session_rng.randint(10, 990)} Juniper Ct, Boise ID 83702"})
        stage = "register"
    else:
        s.get(f"{base_url}/login")
        reply = telemetry("/login", humans.typing_events(session_rng, len(user["email"]) + 12))
        challenge = s.get(f"{base_url}/api/challenge").json()
        counter = solve_challenge(challenge["nonce"], reply["fp_hash"], challenge["difficulty"])
        token = s.post(f"{base_url}/api/challenge/verify",
                       json={"nonce": challenge["nonce"], "counter": counter}).json().get("token") or ""
        r = s.post(f"{base_url}/api/login", json={"email": user["email"], "password": user["password"]},
                   headers={"X-Lab-Token": token})
        stage = "login"
    if r.status_code >= 400 or r.json().get("outcome") != "allow":
        return _result(user, persona, stage, r)

    r = s.get(f"{base_url}{DROP}")
    if r.status_code == 403:
        return _result(user, persona, "page", r)
    opened = time.monotonic()
    low, high = DWELL_S[persona["behavior"]]
    dwell_ms = session_rng.uniform(low, high) * 1000
    if profile.get("events"):  # a real capture: replay its own input, re-aimed at Buy
        events = json.loads(json.dumps(profile["events"]))
        if events.get("clicks"):
            events["clicks"][-1][4] = "buy"
        dwell_ms = max(dwell_ms, max([c[0] for c in events.get("clicks", [])] or [0]) + 150)
    else:
        events = humans.events_for(persona["behavior"], session_rng, dwell_ms)
        last = max([e[0] for e in events["moves"] + events["clicks"] + events["keys"] + events["touches"]] or [0])
        dwell_ms = max(dwell_ms, last + 100)
    time.sleep(max(0.0, dwell_ms / 1000 - (time.monotonic() - opened)))
    telemetry(DROP, events)
    r = s.post(f"{base_url}/api/buy", json={"sku": "lab-runner-9"})
    return _result(user, persona, "buy", r)


def population(batch=0, include_mine=True):
    """(user, persona, profile, batch) tuples for every simulated customer."""
    by_name = {p["name"]: p for p in personas.PERSONAS}
    out = [(u, by_name[u["persona"]], load_profile(by_name[u["persona"]]["profile"]), batch)
           for u in personas.legit_users()]
    mine = os.path.join(PROFILES_DIR, "mine.json")
    if include_mine and os.path.exists(mine):
        profile = load_profile("mine")
        profile.setdefault("headers", {"User-Agent": (profile.get("fp") or {}).get("ua", "")})
        persona = {"name": "mine (captured)", "behavior": "mouse"}
        out.append((personas.MINE_USER, persona, profile, batch))
    return out


def run(batch=0, workers=12, include_mine=True, base_url=BASE_URL):
    """One visit per customer. batch > 0 moves the office NAT to a new IP (used by train_model.py)."""
    ensure_local(base_url)
    jobs = population(batch, include_mine)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(simulate, u, p, prof, b, base_url) for u, p, prof, b in jobs]
        results = []
        for f in futures:
            try:
                results.append(f.result())
            except Exception as exc:  # a crashed simulation is a lab bug, not a false positive
                results.append({"persona": "error", "email": "", "stage": "error", "outcome": "error",
                                "score": None, "reasons": [repr(exc)], "status": None, "score_ms": None})
    return results


def summarize(results):
    by_persona = {}
    for r in results:
        row = by_persona.setdefault(r["persona"], {"allow": 0, "challenge": 0, "block": 0, "other": 0})
        key = r["outcome"] if r["outcome"] in ("allow", "challenge", "block") else "other"
        row[key] += 1
    return by_persona


if __name__ == '__main__':
    started = time.time()
    results = run()
    print(f"=== {len(results)} simulated customers in {time.time() - started:.1f} s ===")
    for name, row in summarize(results).items():
        flag = "✅" if row["block"] == 0 and row["challenge"] == 0 and row["other"] == 0 else "⚠️ "
        print(f"  {flag} {name:<16} allowed {row['allow']}  challenged {row['challenge']}  "
              f"blocked {row['block']}  other {row['other']}")
    for r in results:
        if r["outcome"] != "allow":
            print(f"     {r['persona']:<16} {r['stage']:<8} {r['outcome']:<9} {r['reasons'][:3]}")
