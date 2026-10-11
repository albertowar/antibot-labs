"""
Chapter 4 — Legitimate Traffic Simulator (Section 4.7)

Measures the other half of every defense: how many REAL users it blocks.

Replays 40 synthetic shoppers from tools/profiles/*.json against the demo
store. Each one loads the page, posts its fingerprint with headers that
match it (User-Agent, Sec-CH-UA from its userAgentData, Accept-Language
from its languages), and signs up once. The cohorts are chosen to hurt:

    chrome-windows     8  different Windows PCs
    chrome-mac         4  identical MacBook Air M2s
    corporate-fleet    4  identical office laptops behind ONE IP
    iphone             8  identical iPhones (Safari 26, AFP noise)
    safari-mac         4  Safari 26 with AFP noise
    firefox-fpp        4  Firefox, canvas randomised per session
    brave              4  Brave, canvas/audio farbled per session
    vdi                2  Citrix desktops with a software renderer
    privacy-extension  2  Chrome + a canvas-noise extension (patched natives)

Profiles marked "synthesized" were built from documented browser behaviour
plus real Chromium/Firefox captures, not captured on that exact device.
Add your own browser with the /fp-profile download (Round 0): it then
counts as one more real user in every checkpoint.

Noise is simulated per profile:
    per_session  new canvas/audio values for each visit, identical within it
    per_call     the canvas changes even between two draws in one visit

Run the demo site first, then:
    python tools/legit_traffic.py
"""

import copy
import glob
import hashlib
import json
import os
import sys
import re

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

PROFILES_DIR = os.path.join(os.path.dirname(__file__), "profiles")
NONCE = re.compile(r'data-fp-nonce="([0-9a-f]+)"')


def load_profiles():
    profiles = []
    for path in sorted(glob.glob(os.path.join(PROFILES_DIR, "*.json"))):
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
    """The headers this browser would send with its fetch() to /api/fp."""
    nav, uad = fp["nav"], fp.get("uad")
    langs = nav.get("languages") or ["en-US"]
    accept_language = ",".join(
        [langs[0]] + [f"{lang};q={max(0.1, 0.9 - 0.1 * i):.1f}" for i, lang in enumerate(langs[1:])])
    headers = {"User-Agent": nav["userAgent"], "Accept-Language": accept_language}
    if uad:  # only Chromium-based browsers send Client Hints
        brands = ", ".join(f'"{b.split("/")[0]}";v="{b.split("/")[1]}"' for b in uad["brands"])
        headers.update({"Sec-CH-UA": brands, "Sec-CH-UA-Mobile": "?1" if uad.get("mobile") else "?0",
                        "Sec-CH-UA-Platform": f'"{uad["platform"]}"'})
    return headers


def visit_and_sign_up(fp, ip, email):
    """One real user's visit: page load, fingerprint, sign-up."""
    headers = {**headers_for(fp), "X-Lab-Client-IP": ip}
    with httpx.Client(base_url=BASE_URL, headers=headers, timeout=10) as client:
        page = client.get("/")
        fp["nonce"] = NONCE.search(page.text).group(1)
        client.post("/api/fp", json=fp).raise_for_status()
        r = client.post("/signup", json={"email": email, "password": "Synthetic-Passw0rd!"})
        timing = dict(re.findall(r"(\w+);dur=([\d.]+)", r.headers.get("Server-Timing", "")))
        return r.status_code, r.json(), {k: float(v) for k, v in timing.items()}


def run():
    """Sign up every simulated user once. Returns one result per user."""
    results = []
    user_no = 0
    for profile in load_profiles():
        for n, fp in enumerate(expand_users(profile)):
            user_no += 1
            fp = apply_noise(fp, profile.get("noise", "none"), seed=user_no)
            ip = "198.51.100.10" if profile.get("ip") == "shared" else f"198.51.100.{100 + user_no}"
            email = f"{profile['cohort']}-{n + 1}@example.test"
            status, body, timing = visit_and_sign_up(fp, ip, email)
            results.append({"cohort": profile["cohort"], "user": n + 1, "status": status,
                            "verdict": body.get("verdict"), "score": body.get("score"),
                            "reasons": body.get("reasons", []), "timing": timing,
                            "collect_ms": fp.get("collect_ms"),
                            "payload_bytes": len(json.dumps(fp))})
    return results


def summarize(results):
    """{cohort: (users, blocked, suspicious)} in profile order."""
    cohorts = {}
    for r in results:
        users, blocked, suspicious = cohorts.get(r["cohort"], (0, 0, 0))
        cohorts[r["cohort"]] = (users + 1, blocked + (r["status"] == 403),
                                suspicious + (r["verdict"] == "suspicious"))
    return cohorts


if __name__ == '__main__':
    results = run()
    if not results:
        raise SystemExit(f"No profiles found in {PROFILES_DIR}")
    print("=== Legitimate users (40 synthetic shoppers + your own profiles) ===")
    for cohort, (users, blocked, suspicious) in summarize(results).items():
        mark = "✅" if not blocked else "❌"
        print(f"  {mark} {cohort:<18} {blocked}/{users} blocked, {suspicious} suspicious")
        for r in results:
            if r["cohort"] == cohort and r["verdict"] != "clean":
                print(f"       user {r['user']}: {r['verdict']} ({r['score']}) {r['reasons'][:2]}")
    blocked = sum(r["status"] == 403 for r in results)
    print(f"\n  False positives: {blocked}/{len(results)} real users refused")
