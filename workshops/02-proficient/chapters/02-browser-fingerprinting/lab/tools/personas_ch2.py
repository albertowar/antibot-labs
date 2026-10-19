"""
Chapter 2 shoppers: the 40 population personas, each signing up as a real browser profile.

tools/population.py's shoppers are Python, not browsers, so nobody runs the sign-up page's
collector for them. This file registers the scenario "fp_signup": each shopper replays one real
user of tools/profiles/*.json. It loads the sign-up page with the profile's own headers
(User-Agent, Sec-CH-UA from its userAgentData, Accept-Language from its languages), posts the
profile's fingerprint to /api/telemetry like the collector would, waits as long as the collector
took, and registers once. The persona keeps its own label, so the scoreboard still counts it as
a human, and the persona's own browser never leaks into the headers.

The cohorts are chosen to hurt (profile files, who they are):

    chrome-windows     7  different Windows PCs (of the profile's eight)
    chrome-mac         4  identical MacBook Air M2s
    corporate-fleet    4  identical office laptops behind ONE address
    iphone             8  identical iPhones (Safari 26, AFP noise): the 8 mobile_cgnat shoppers
    safari-mac         4  Safari 26 with AFP noise
    firefox-fpp        4  Firefox, canvas randomised per session
    brave              4  Brave, canvas/audio farbled per session
    vdi                2  Citrix desktops with a software renderer
    privacy-extension  2  Chrome + a canvas-noise extension (patched natives)
    (no profile)       1  the no_js shopper: JavaScript off, so no fingerprint at all

Profiles marked "synthesized" were built from documented browser behaviour plus real Chromium and
Firefox captures, not captured on that exact device. Add your own browser with /lab/fp/profile
(Round 0): tools/profiles/you-*.json is replayed by the checkpoint as one more real user, and a
refusal of it is a bug in the defense.

Noise is simulated per profile:
    per_session  new canvas/audio values for each visit, identical within it
    per_call     the canvas changes even between two draws in one visit

Outcomes (from the register call):

    registered   201: the account was created (the gate may have flagged it "monitor")
    blocked      403: a false positive, except the no_js shopper from Round 1 on (an accepted cost)

    python tools/personas_ch2.py                  # once, at the store's current level, per cohort
"""

import copy
import glob
import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import population  # noqa: E402
from labclient import BASE_URL, LabClient, world_pool  # noqa: E402

PROFILES_DIR = os.path.join(HERE, "profiles")
NONCE_RE = re.compile(r'__fpNonce = "([0-9a-f]+)"')
PASSWORD = "Synthetic-Passw0rd!"
NO_PROFILE = "no_js"

population.HAPPY.add("registered")


def load_profiles(own=False):
    """The cohort profiles (tools/profiles/*.json), or your own captures (you-*.json) with own=True."""
    profiles = []
    for path in sorted(glob.glob(os.path.join(PROFILES_DIR, "*.json"))):
        mine = os.path.basename(path).startswith("you-")
        if mine != own:
            continue
        with open(path) as f:
            data = json.load(f)
        data.setdefault("cohort", os.path.splitext(os.path.basename(path))[0])
        profiles.append(data)
    return profiles


def expand_users(profile):
    """One payload per simulated user (a {"payload", "count"} entry is `count` people)."""
    for entry in profile["users"]:
        for _ in range(entry.get("count", 1)):
            yield copy.deepcopy(entry["payload"])


def _h(*parts):
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def apply_noise(fp, mode, seed):
    """What a privacy browser does to the render hashes on each visit."""
    if mode == "none":
        return fp
    canvas, audio = fp["canvas"], fp["audio"]
    canvas["hash"] = _h(canvas["hash"], "noise", seed)
    canvas["hash2"] = canvas["hash"] if mode == "per_session" else _h(canvas["hash"], "2nd draw")
    canvas["probeChangedPixels"] = 3 + seed % 5
    if audio.get("supported"):
        audio["sum"] = round(audio["sum"] + (seed % 97) * 1e-6, 6)
        audio["hash"] = _h(audio["hash"], "noise", seed)
    return fp


def headers_for(fp):
    """The headers this browser sends with every request of the visit, in the order it sends them."""
    nav, uad = fp["nav"], fp.get("uad")
    langs = nav.get("languages") or ["en-US"]
    accept_language = ",".join(
        [langs[0]] + [f"{lang};q={max(0.1, 0.9 - 0.1 * i):.1f}" for i, lang in enumerate(langs[1:])])
    headers = [("User-Agent", nav["userAgent"]), ("Accept-Language", accept_language)]
    if uad:                                 # only Chromium-based browsers send Client Hints
        brands = ", ".join(f'"{b.split("/")[0]}";v="{b.split("/")[1]}"' for b in uad["brands"])
        headers += [("Sec-CH-UA", brands), ("Sec-CH-UA-Mobile", "?1" if uad.get("mobile") else "?0"),
                    ("Sec-CH-UA-Platform", f'"{uad["platform"]}"')]
    return headers


def assignments():
    """actor -> (cohort, shared_ip, payload, noise) for the 40 personas; no_js maps to None. Deterministic."""
    people = population.personas()
    profiles = {p["cohort"]: p for p in load_profiles()}
    users = {name: list(expand_users(p)) for name, p in profiles.items()}
    # iPhones take the carrier-NAT shoppers; the rest are dealt out in actor order
    plan = ["chrome-windows"] * 7 + ["chrome-mac"] * 4 + ["corporate-fleet"] * 4 + ["safari-mac"] * 4 + \
           ["firefox-fpp"] * 4 + ["brave"] * 4 + ["vdi"] * 2 + ["privacy-extension"] * 2
    out, seen, k = {}, {}, 0
    for p in sorted(people, key=lambda p: p.actor):
        if p.persona == NO_PROFILE:
            out[p.actor] = None
            continue
        cohort = "iphone" if p.persona == "mobile_cgnat" else plan[k]
        k += 0 if p.persona == "mobile_cgnat" else 1
        n = seen[cohort] = seen.get(cohort, 0) + 1
        prof = profiles[cohort]
        out[p.actor] = (cohort, prof.get("ip") == "shared", users[cohort][n - 1], prof.get("noise", "none"), len(out) + 1)
    return out


_ASSIGNED = {}
_LOCK = threading.Lock()


def parse_timing(header):
    return {k: float(v) for k, v in re.findall(r"([\w-]+);dur=([\d.]+)", header or "")}


def sign_up(client, fp, ip, email):
    """One real user's visit: sign-up page, fingerprint, sign-up. Returns the register response."""
    headers = headers_for(fp) if fp else []
    page = client.get("/register", headers, ip=ip)
    m = NONCE_RE.search(page.text)
    if fp and m:                                              # a browser with JavaScript runs the collector
        fp["nonce"] = m.group(1)
        client.post("/api/telemetry", json=dict(fp, kind="fp"), ip=ip,
                    headers=headers + [("Content-Type", "application/json")])
        time.sleep(min(0.4, (fp.get("collect_ms") or 0) / 1000))      # the collector's own run time, capped
    return client.post("/api/register", json={"email": email, "password": PASSWORD, "name": "Pat Shopper"}, ip=ip,
                       headers=headers + [("Content-Type", "application/json")])


def scenario_fp_signup(p, client, rng):
    with _LOCK:
        if not _ASSIGNED:
            _ASSIGNED.update(assignments())
    plan = _ASSIGNED.get(p.actor)
    time.sleep(rng.uniform(0, 3))
    if plan is None:                                          # JavaScript off: no collector, no fingerprint
        p.result["cohort"] = NO_PROFILE
        r = sign_up(client, None, None, f"{NO_PROFILE}.{secrets.token_hex(3)}@example.test")
    else:
        cohort, shared, fp, noise, seed = plan
        p.result["cohort"] = cohort
        fp = apply_noise(fp, noise, seed)
        ip = world_pool("corporate")[0] if shared else None
        r = sign_up(client, fp, ip, f"{cohort}.{secrets.token_hex(3)}@example.test")
    timing = parse_timing(r.headers.get("Server-Timing"))
    p.result.update(score=int(r.headers.get("X-Lab-Score") or 0), signals=r.headers.get("X-Lab-Signals", ""),
                    gate_ms=timing.get("gate"), timing=timing, verdict_name=r.headers.get("X-Lab-Verdict"))
    if r.status_code == 201:
        return population._stop(p, client, "registered", r)
    return population._stop(p, client, "blocked" if r.status_code in (403, 429) else "failed", r)


population.SCENARIOS["fp_signup"] = scenario_fp_signup


def run_own(rng_seed=11):
    """Sign up once as each of your own captured profiles (tools/profiles/you-*.json). Returns result dicts."""
    import random
    rng = random.Random(rng_seed)
    out = []
    for prof in load_profiles(own=True):
        for n, fp in enumerate(expand_users(prof)):
            client = LabClient(f"human:you:{n:02d}", ip=world_pool("home_eu")[n % 60], rng=rng)
            fp = apply_noise(fp, prof.get("noise", "none"), 900 + n)
            r = sign_up(client, fp, None, f"you.{prof['cohort']}.{secrets.token_hex(3)}@example.test")
            out.append({"cohort": prof["cohort"], "status": r.status_code,
                        "score": int(r.headers.get("X-Lab-Score") or 0), "signals": r.headers.get("X-Lab-Signals", "")})
    return out


def summarize(results):
    """{cohort: (users, blocked, flagged)} in first-seen order; flagged = the gate said monitor (20-39)."""
    cohorts = {}
    for r in sorted(results, key=lambda r: (r.get("cohort", "?"), r["actor"])):
        users, blocked, flagged = cohorts.get(r.get("cohort", "?"), (0, 0, 0))
        cohorts[r.get("cohort", "?")] = (users + 1, blocked + (r.get("outcome") == "blocked"),
                                         flagged + (r.get("verdict_name") == "monitor"))
    return cohorts


if __name__ == "__main__":
    results = population.run("fp_signup", quiet=True)
    print("=== The 40 shoppers, signing up (at the store's current level) ===")
    for cohort, (users, blocked, flagged) in summarize(results).items():
        mark = "ok  " if not blocked else "FAIL"
        print(f"  {mark} {cohort:<18} {blocked}/{users} refused, {flagged} flagged")
        for r in results:
            if r.get("cohort") == cohort and (r.get("outcome") == "blocked" or r.get("verdict_name") == "monitor"):
                print(f"       {r['outcome']:<10} score {r.get('score')}  {r.get('signals')}")
    print(f"\n  Refused: {sum(r.get('outcome') == 'blocked' for r in results)}/{len(results)} real users")
