"""
Chapter 6 — Legitimate-traffic simulator: 40 synthetic shoppers

Every round reports what the defense costs real people, next to what it
stops. Each simulated shopper visits the store, signs up, and claims the
promo voucher, the way a person would:

  - reads the CAPTCHA through labkit.look_at() (simulated eyes) and gets it
    right with HUMAN_ACCURACY for the current style; a miss is a plausible typo
  - takes a lognormal 3–15 s to read and type (median ~6 s, simulated)
  - gives up after a failed CAPTCHA 25% of the time (abandonment)

The population is fixed (seeded) so rounds are comparable:
  4 deep-linkers   arrive from an email link straight to the promo,
                   skipping the landing page
  1 network hopper one of the deep-linkers, on a phone: Wi-Fi → cellular
                   between loading and submitting the CAPTCHA, so the
                   submitting IP changes
  2 screen-reader  cannot solve an image CAPTCHA at all. This lab has no
    users          audio or alternative path, so every time they are
                   challenged, they are lost. That is the accessibility cost.

Simulated humans are a model, not data. Treat the numbers as the shape of
the trade-off, and measure your own users before you set thresholds.

Run:  python tools/legit_traffic.py
"""

import math
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from labkit import (HUMAN_NET, client, look_at, mint_token, new_email, random_ip,  # noqa: E402
                    require_local, server_timing, sim_now, sim_sleep, typo)

N_USERS = 40
ABANDON_AFTER_FAIL = 0.25
# First-try reading accuracy per generator style. An assumption, in the
# range Bursztein et al. measured for distorted text (2010).
HUMAN_ACCURACY = {"basic": 0.97, "hardened": 0.88}
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/153.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/26.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:155.0) Gecko/20100101 Firefox/155.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/26.0 Mobile/15E148 Safari/604.1",
]


def population(seed=6):
    rng = random.Random(seed)
    users = []
    for i in range(N_USERS):
        users.append({
            "id": i, "ip": random_ip(HUMAN_NET, rng), "ua": rng.choice(UAS),
            "deep_link": i in (3, 11, 19, 27), "hopper": i == 3,
            "screen_reader": i in (15, 33), "seed": seed * 1000 + i,
        })
    return users


def read_time(rng):
    return min(15.0, max(3.0, rng.lognormvariate(math.log(6.0), 0.35)))


def shopper(user, level, style):
    rng = random.Random(user["seed"])
    c = client(user["ip"], user["ua"], "human")
    out = {"user": user["id"], "registered": False, "redeemed": False, "lost": None,
           "challenges": 0, "timings": [], "started": sim_now()}
    try:
        if not user["deep_link"]:
            c.get("/")
            sim_sleep(rng.uniform(2, 5))           # browse
        form = {"email": new_email(f"u{user['id']}"), "password": "correct horse battery"}
        if level >= 1:
            form["cf-turnstile-response"] = mint_token(user["ip"], "register")
        sim_sleep(rng.uniform(4, 9))                # fill in the form
        r = c.post("/register", data=form)
        out["timings"].append(server_timing(r))
        out["registered"] = r.status_code == 201
        if not out["registered"]:
            out["lost"] = f"register: {r.json().get('error')}"
            return out

        c.get("/promo/unlock")
        sim_sleep(rng.uniform(1, 3))
        for _ in range(4):                          # initial try + step-ups / retries
            needs = c.get("/promo/status").json()["challenge_required"]
            cid, answer = "", ""
            if needs:
                out["challenges"] += 1
                if user["screen_reader"]:
                    out["lost"] = "inaccessible: image-only CAPTCHA"
                    return out
                r = c.get("/captcha/new")
                out["timings"].append(server_timing(r))
                cid = r.json()["id"]
                sim_sleep(read_time(rng))
                seen = look_at(cid) or ""
                answer = seen if rng.random() < HUMAN_ACCURACY[style] else typo(seen, rng)
                if user["hopper"] and out["challenges"] == 1:
                    c.headers["X-Lab-Client-IP"] = random_ip(HUMAN_NET, rng)   # Wi-Fi → 5G
            r = c.post("/promo/redeem", data={"captcha_id": cid, "captcha": answer})
            out["timings"].append(server_timing(r))
            body = r.json()
            if r.status_code == 200:
                out["redeemed"] = True
                return out
            if body.get("error") == "blocked":
                out["lost"] = "blocked: " + "; ".join(body.get("reasons", []))
                return out
            if body.get("error") != "step_up" and rng.random() < ABANDON_AFTER_FAIL:
                out["lost"] = f"abandoned after: {body.get('error')}"
                return out
        out["lost"] = "gave up after repeated challenges"
        return out
    finally:
        out["seconds_sim"] = sim_now() - out["started"]
        c.close()


def run(seed=6):
    """Simulate every shopper concurrently. Returns one result dict per user."""
    require_local()
    import httpx
    from labkit import BASE_URL
    status = httpx.get(f"{BASE_URL}/lab/status", timeout=5).json()
    with ThreadPoolExecutor(N_USERS) as pool:
        return list(pool.map(lambda u: shopper(u, status["level"], status["style"]),
                             population(seed)))


def summarize(results):
    lost = [r for r in results if r["lost"]]
    return {
        "users": len(results),
        "completed": sum(r["redeemed"] for r in results),
        "challenged": sum(r["challenges"] > 0 for r in results),
        "challenges": sum(r["challenges"] for r in results),
        "lost": lost,
        "median_s": sorted(r["seconds_sim"] for r in results)[len(results) // 2],
    }


if __name__ == "__main__":
    start = time.perf_counter()
    results = run()
    s = summarize(results)
    print(f"=== {s['users']} simulated shoppers ({time.perf_counter() - start:.1f} s real) ===")
    print(f"  completed {s['completed']}/{s['users']} · challenged {s['challenged']}/{s['users']} "
          f"· {s['challenges']} CAPTCHAs shown · median journey {s['median_s']:.0f} s")
    for r in s["lost"]:
        print(f"  ❌ user {r['user']:>2}: {r['lost']}")
