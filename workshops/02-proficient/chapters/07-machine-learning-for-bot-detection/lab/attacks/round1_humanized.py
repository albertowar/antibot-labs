"""
Chapter 7 — Round 1 Attack: the humanized bot (Section 7.6, Part 2)

Objective: beat model v1 without touching a single rule. The attacker
has read the same papers you have:

  - residential proxy exits geo-targeted to the US ($4/GB, simulated)
  - one carefully built stealth profile: a common Windows + NVIDIA + Chrome
    fingerprint with a New York locale, fully consistent
  - behavior sampled from human-like distributions (curved mouse paths,
    jittered typing, scrolling), log-normal think times, browses a few
    products before the drop
  - never follows hidden links, never calls disallowed APIs

Why it works: v1 was trained on honeypot-labeled bots. Nothing that looks
like this session was ever labeled "bot", so per-session features say
"human". The model is only as good as its labels.

Its weakness (for Round 2): ONE profile reused for every session.

Expected results:
  - DEFENSE_LEVEL=1 → most checkouts succeed (≈ 80–100%)
  - DEFENSE_LEVEL=2 → ≤ 10% succeed (cohort features + cluster labels)

Run:
    python attacks/round1_humanized.py
"""

import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import labclient as labnet  # noqa: E402
import shopper  # noqa: E402
from shopper import (UA, Persona, browser_headers, desktop_behavior,  # noqa: E402
                     fingerprint, human_think)

PROFILE_SEED = 42  # the one stealth profile the operator built


def stealth_profile():
    rng = random.Random(PROFILE_SEED)
    locale = shopper.LOCALES[1]  # America/New_York
    return fingerprint(rng, "win-nvidia", locale, "chrome_win"), locale


def personas(n=60, seed=0):
    rng = random.Random(seed + 1000)
    fp, locale = stealth_profile()
    pool = labnet.Pool("residential", country="US", rng=rng)
    out = []
    for _ in range(n):
        ip, _ = pool.next()
        out.append(Persona(actor="round1_humanized", cohort="humanized", is_bot=True, ip=ip,
                           user_agent=UA["chrome_win"], headers=browser_headers(locale[1]),
                           fp=dict(fp), behavior=desktop_behavior(rng),
                           think=human_think(6.0), browse=rng.randint(1, 5),
                           usd_per_gb=pool.usd_per_gb))
    return out


def run(n=40, seed=21):
    """Run the attack; return one result per session (used by tools/checkpoint.py)."""
    return shopper.run_sessions(personas(n, seed), seed=seed, run="round1_humanized")


if __name__ == "__main__":
    print(f"=== Round 1: humanized bot, one stealth profile, residential US → {labnet.target()} ===")
    results = run(n=60, seed=20)
    ok = sum(shopper.succeeded(r) for r in results)
    usd = sum(r["usd"] for r in results)
    print(f"  checkouts succeeded: {ok}/{len(results)}   proxy bill ≈ ${usd:.2f} (simulated)")
    blocked = [r["score"] for r in results if r["score"] is not None]
    if blocked:
        print(f"  risk returned by the server (teaching aid): "
              f"min {min(blocked):.2f}  max {max(blocked):.2f}")
