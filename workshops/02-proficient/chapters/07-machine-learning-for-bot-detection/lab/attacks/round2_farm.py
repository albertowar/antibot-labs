"""
Chapter 7 — Round 2 Attack: the fingerprint-rotating farm (Section 7.6, Part 3)

Objective: beat the cohort features of model v2. The operator learned
that one profile reused 60 times is a cluster, so every session now gets a
fresh profile from an anti-detect browser's "randomize" button:

  - every attribute (platform, GPU, screen, timezone, languages, UA) is
    drawn independently from a list of real-world values
  - canvas hash randomized per session
  - same humanized behavior and residential US exits as Round 1

Why it works: every cohort count is 1. Per-session behavior still looks
human. And v2 never saw a labeled bot with inconsistent claims, so it
learned nothing about consistency features.

Its weakness (for Round 3): independently randomized attributes produce
combinations no real device has: an Apple GPU on Win32, a phone with no
touch points, a Berlin timezone on a US home ISP.

Expected results:
  - DEFENSE_LEVEL=2 → most checkouts succeed (≈ 70–100%)
  - DEFENSE_LEVEL=3 → ≤ 15% succeed (anomaly detector trained on humans)

Run:
    python attacks/round2_farm.py
"""

import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import labnet  # noqa: E402
import shopper  # noqa: E402
from shopper import UA, Persona, browser_headers, desktop_behavior, human_think  # noqa: E402

ALL_SCREENS = sorted({s for d in shopper.DEVICES.values() for s in d[2]})
ALL_GPUS = sorted({d[1] for d in shopper.DEVICES.values()})
ALL_PLATFORMS = sorted({d[0] for d in shopper.DEVICES.values()})


def randomized_profile(rng):
    """Naive rotation: each attribute on its own. Unique, and often impossible."""
    tz, langs, _cc, _w = rng.choice(shopper.LOCALES)
    ua_key = rng.choice(list(UA))
    return ua_key, langs, {
        "platform": rng.choice(ALL_PLATFORMS), "ua": UA[ua_key], "gpu": rng.choice(ALL_GPUS),
        "screen": rng.choice(ALL_SCREENS), "dpr": rng.choice([1.0, 1.25, 2.0, 3.0]),
        "tz": tz, "langs": langs, "hw": rng.choice([4, 8, 12, 16]),
        "touch": rng.choice([0, 5, 10]), "webdriver": False,
        "canvas": f"{rng.getrandbits(64):016x}",
    }


def personas(n=60, seed=0):
    rng = random.Random(seed + 2000)
    pool = labnet.Pool("residential", country="US", rng=rng)
    out = []
    for _ in range(n):
        ip, _ = pool.next()
        ua_key, langs, fp = randomized_profile(rng)
        out.append(Persona(actor="round2_farm", cohort="farm", is_bot=True, ip=ip,
                           user_agent=UA[ua_key], headers=browser_headers(langs), fp=fp,
                           behavior=desktop_behavior(rng), think=human_think(6.0),
                           browse=rng.randint(1, 5), usd_per_gb=pool.usd_per_gb))
    return out


def run(n=40, seed=31):
    """Run the attack; return one result per session (used by tools/checkpoint.py)."""
    return shopper.run_sessions(personas(n, seed), seed=seed, run="round2_farm")


if __name__ == "__main__":
    print(f"=== Round 2: rotating-fingerprint farm, residential US → {labnet.target()} ===")
    results = run(n=60, seed=30)
    ok = sum(shopper.succeeded(r) for r in results)
    usd = sum(r["usd"] for r in results)
    print(f"  checkouts succeeded: {ok}/{len(results)}   proxy bill ≈ ${usd:.2f} (simulated)")
