"""
A real customer who mistypes their password (Round 4's false-positive exercise).

    python tools/mistype.py                   # two typos, then the right password
    python tools/mistype.py --typos 4 --profile chrome-153-macos

The customer shops as one of the browsers every shopper replays (tools/profiles, Chapter 1), so its fingerprint
cluster is SHARED with the shoppers who use the same profile: that is how identical corporate laptops look to
defenses/login_risk.py. At the shipped numbers (5 failures and a 50 % failure ratio in 10 minutes) two or four
typos change nothing; tighten CLUSTER_MIN_FAILURES and CLUSTER_MAX_FAILURE_RATIO in defenses/policy.py and the
login that follows is refused, for this customer and for everyone who shares the cluster.

Prints one line per attempt and one JSON line at the end ({"attempted": n, "succeeded": 0 or 1, ...}).
"""

import argparse
import json
import re

import personas_ch9  # noqa: F401  (also puts the lab root on sys.path)
import profile_replay
from labclient import LabClient, world_pool

NONCE = re.compile(r"ShopSensor\.send\(\"([^\"]+)\"\)")


def run(typos, profile, level_hint=None):
    from demo_site.seed import password_for, username
    prof = profile_replay.profile(profile)
    c = LabClient("human:mistype", ip=world_pool("home_broadband")[40])
    c.ja4 = personas_ch9.CLAIMED_JA4[personas_ch9.family(profile)]
    nav = profile_replay.headers(c, prof["navigation_headers"])
    post = profile_replay.headers(c, prof["post_headers"])
    fetch = profile_replay.headers(c, prof["fetch_headers"])
    m = NONCE.search(c.get("/", nav).text)
    c.post("/api/telemetry", headers=post, json={"kind": "sensor", "nonce": m.group(1), "signals": prof["signals"]})
    codes = []
    for attempt in range(typos + 1):
        token = personas_ch9._login_token(c, fetch, post)
        password = password_for(31) if attempt == typos else password_for(31) + "x" * (attempt + 1)
        r = c.post("/api/login", headers=post + [("X-Login-Token", token)], json={"email": username(31), "password": password})
        codes.append(r.status_code)
        print(f"  attempt {attempt + 1}: {'right' if attempt == typos else 'wrong'} password -> {r.status_code} {r.headers.get('X-Lab-Signals', '')}")
    return codes


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--typos", type=int, default=2)
    ap.add_argument("--profile", default="chrome-153-macos")
    a = ap.parse_args()
    codes = run(a.typos, a.profile)
    print(json.dumps({"attack": "mistype", "attempted": len(codes), "succeeded": int(codes[-1] == 200), "codes": codes}))
