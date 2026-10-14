"""
Round 0 attack: the bots you already know

Two scalper families from earlier chapters, running on cheap cloud servers:

  naive_scalper     a script (python-requests, or a borrowed Chrome User-Agent and nothing else): no JS,
                    no assets, metronome pacing. Crawls every link on the home page, including the
                    hidden honeypot link (W1 Ch8), and pokes the endpoint robots.txt disallows.
  headless_scalper  automated Chrome with the webdriver flag patched (W2 Ch1): loads assets, runs the
                    page collector, but barely moves the mouse and fills forms instantly. Often
                    renders with SwiftShader (no GPU in the cloud). Rarely falls for the honeypot.

`tools/simulate.py` mixes these into every drop day. Their honeypot hits are the defender's only bot
labels, so the model will learn what THESE bots look like, and nothing else. That bias is the
vulnerability Round 1 exploits.

Expected results:
  - DEFENSE_LEVEL=0  -> every purchase succeeds
  - DEFENSE_LEVEL>=1 -> at most a few percent succeed (the model was trained on them)

Run:
    python attacks/round0_baseline.py
"""

import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))

import labclient  # noqa: E402  (runs the labnet guard)
import shopper  # noqa: E402
from shopper import UA, Persona, accept_language, fingerprint, fixed_think  # noqa: E402

HISTORY_SEED = 1
SWIFTSHADER = "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)"
NEW_YORK = shopper.LOCALES[1]


def scripted_behavior(rng):
    """What `page.click()` and `page.fill()` produce: almost nothing."""
    moves = rng.randint(0, 4)
    return {"mouse_moves": moves, "straightness": 1.0 if moves else None,
            "speed_cv": round(rng.uniform(0.0, 0.05), 3) if moves else None,
            "clicks": rng.randint(2, 3), "keys": 0, "key_cv": None,
            "touches": 0, "scrolls": 0, "first_input_ms": rng.randint(30, 120)}


def naive_scalper(rng, n):
    ip = rng.choice(labclient.world_pool("cloud_vm"))
    ua = "python-requests/2.34.2" if rng.random() < 0.5 else UA["chrome_win"]  # a borrowed Chrome UA, nothing else (W1 Ch4)
    return Persona(actor=f"bot:naive_scalper:{n:03d}", persona="naive_scalper", browser=("script",), ip=ip, ua=ua,
                   browser_like=False, accept_language=None, fp=None, behavior=None, think=fixed_think(1.0),
                   browse=0, loads_assets=False, honeypot=0.7, partner_feed=0.3, usd_per_gb=0.10)


def headless_scalper(rng, n, canvas):
    ip = rng.choice(labclient.world_pool("cloud_vm"))
    device, ua_key = rng.choice([("win-nvidia", "chrome_win"), ("linux-intel", "chrome_linux")])
    fp = fingerprint(rng, device, NEW_YORK, ua_key, canvas=canvas)
    if rng.random() < 0.6:
        fp["gpu"] = SWIFTSHADER
    return Persona(actor=f"bot:headless_scalper:{n:03d}", persona="headless_scalper", browser=("headless",), ip=ip,
                   ua=UA[ua_key], accept_language=accept_language(NEW_YORK[1]), fp=fp, behavior=scripted_behavior(rng),
                   think=fixed_think(0.8), browse=rng.randint(0, 1), loads_assets=True, honeypot=0.25, usd_per_gb=0.10)


def personas(n_each=150, seed=0):
    rng = random.Random(seed + 500)
    # One container image -> one canvas hash for the whole headless fleet
    canvas = f"{rng.getrandbits(64):016x}"
    return ([naive_scalper(rng, i) for i in range(n_each)]
            + [headless_scalper(rng, i, canvas) for i in range(n_each)])


def run(n_each=30, seed=11):
    """Run the attack; return one result per session (also used by tools/simulate.py)."""
    return shopper.run_sessions(personas(n_each, seed), seed=seed)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="The baseline scalpers.")
    parser.add_argument("--n", type=int, default=30, help="sessions per family")
    parser.add_argument("--seed", type=int, default=11)
    args = parser.parse_args()
    print(f"=== Round 0: baseline scalpers -> {labclient.BASE_URL} ===")
    results = run(args.n, args.seed)
    for family in ("naive_scalper", "headless_scalper"):
        mine = [r for r in results if r["persona"] == family]
        print(f"  {family:<18} purchases succeeded: {sum(shopper.succeeded(r) for r in mine)}/{len(mine)}")
    print(json.dumps(shopper.summarize_attack(results)))
