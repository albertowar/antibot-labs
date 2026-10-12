"""
Chapter 7 — Round 0 Attack: the bots you already know (Section 7.6, Part 1)

Two scalper families from earlier chapters, running on cheap cloud servers:

  naive_scalper     httpx script: no JS, no assets, metronome pacing.
                    Crawls every link on the home page, including the
                    hidden honeypot link (W1 Ch7), and pokes the API that
                    robots.txt disallows.
  headless_scalper  automated Chrome with the webdriver flag patched
                    (W2 Ch1): loads assets, runs the page collector, but
                    barely moves the mouse and fills forms instantly.
                    Often renders with SwiftShader (no GPU in the cloud).
                    Rarely falls for the honeypot.

`tools/simulate.py` mixes these into every drop day. Their honeypot hits
are the defender's only bot labels, so the model will learn what THESE bots
look like, and nothing else. That bias is the vulnerability Round 1 exploits.

Expected results:
  - DEFENSE_LEVEL=0 → every checkout succeeds
  - DEFENSE_LEVEL>=1 → ≤ 5% succeed (the model was trained on them)

Run:
    python attacks/round0_baseline.py
"""

import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import labclient as labnet  # noqa: E402
import shopper  # noqa: E402
from shopper import UA, Persona, browser_headers, fingerprint, fixed_think  # noqa: E402

SWIFTSHADER = "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)"


def scripted_behavior(rng):
    """What `page.click()` and `page.fill()` produce: almost nothing."""
    moves = rng.randint(0, 4)
    return {"mouse_moves": moves, "straightness": 1.0 if moves else None,
            "speed_cv": round(rng.uniform(0.0, 0.05), 3) if moves else None,
            "clicks": rng.randint(2, 3), "keys": 0, "key_cv": None,
            "touches": 0, "scrolls": 0, "first_input_ms": rng.randint(30, 120)}


def naive_scalper(rng):
    ip, _ = labnet.Pool("datacenter", rng=rng).next()
    if rng.random() < 0.5:
        ua, headers = "python-httpx/0.28.1", {}
    else:  # borrowed Chrome UA, nothing else (W1 Ch3 Round 2)
        ua, headers = UA["chrome_win"], {"Accept": "*/*"}
    return Persona(actor="round0_baseline", cohort="naive_scalper", is_bot=True, ip=ip,
                   user_agent=ua, headers=headers, fp=None, behavior=None,
                   think=fixed_think(1.0), browse=0, loads_assets=False,
                   honeypot=0.7, api_v0=0.3, usd_per_gb=0.10)


def headless_scalper(rng, canvas):
    ip, _ = labnet.Pool("datacenter", country="US", rng=rng).next()
    device, ua_key = rng.choice([("win-nvidia", "chrome_win"), ("linux-intel", "chrome_linux")])
    locale = shopper.LOCALES[1]  # America/New_York
    fp = fingerprint(rng, device, locale, ua_key, canvas=canvas)
    if rng.random() < 0.6:
        fp["gpu"] = SWIFTSHADER
    return Persona(actor="round0_baseline", cohort="headless_scalper", is_bot=True, ip=ip,
                   user_agent=UA[ua_key], headers=browser_headers(locale[1]), fp=fp,
                   behavior=scripted_behavior(rng), think=fixed_think(0.8),
                   browse=rng.randint(0, 1), loads_assets=True, honeypot=0.25,
                   usd_per_gb=0.10)


def personas(n_each=150, seed=0):
    rng = random.Random(seed + 500)
    # One container image → one canvas hash for the whole headless fleet
    canvas = f"{rng.getrandbits(64):016x}"
    return ([naive_scalper(rng) for _ in range(n_each)]
            + [headless_scalper(rng, canvas) for _ in range(n_each)])


def run(n_each=30, seed=11):
    """Run the attack; return one result per session (used by tools/checkpoint.py)."""
    return shopper.run_sessions(personas(n_each, seed), seed=seed, run="round0_baseline")


if __name__ == "__main__":
    print(f"=== Round 0: baseline scalpers → {labnet.target()} ===")
    results = run()
    for family in ("naive_scalper", "headless_scalper"):
        mine = [r for r in results if r["cohort"] == family]
        ok = sum(shopper.succeeded(r) for r in mine)
        print(f"  {family:<18} checkouts succeeded: {ok}/{len(mine)}")
