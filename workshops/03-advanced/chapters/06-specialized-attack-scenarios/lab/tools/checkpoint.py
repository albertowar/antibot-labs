"""Round checkpoint — run at the end of every round, measuring BOTH sides.

For the chosen round it resets the store, runs the legitimate customers, then
resets again and runs the attacker, so each side is measured against a clean slate
and the two never contend for the same stock. It then prints:

    bots:   what the attacker achieved (takeovers / pairs / items / accounts / clicks)
    humans: how the real customers fared (allowed / challenged / blocked)
    verdict: a round passes when the attack is stopped at its scenario signature AND
             no legitimate customer is blocked. A challenge is friction, not failure,
             except where noted.

Fell behind, or want to see the finished defense?
    python tools/checkpoint.py --round 2 --catch-up   # install the reference solution
    python tools/checkpoint.py --round 2              # restores your work, tests it

Run with the demo store already running (python demo_site/app.py).
"""

from __future__ import annotations

import argparse
import importlib
import os
import shutil
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
sys.path.insert(0, HERE)
from _common import BASE_URL, require_local  # noqa: E402
import legit_traffic  # noqa: E402

# round -> (defense module, attack module, attack kwargs, metric label, bot endpoints)
ROUNDS = {
    1: ("breached_passwords", "round1_stuffer", {}, "account takeovers", {"login"}),
    2: ("scalping_funnel", "round2_scalper", {}, "pairs won", {"checkout"}),
    3: ("scrape_defense", "round3_scraper", {}, "items harvested", {"products", "product"}),
    4: ("account_cluster", "round4_account_farm", {}, "fake accounts created", {"register"}),
    5: ("ivt_scoring", "round5_click_fraud", {}, "fraudulent clicks counted", {"click"}),
}
# round -> max bot "successes" that still counts as stopped
BOT_CEILING = {1: 0, 2: 4, 3: 30, 4: 0, 5: 0}


def manage_solution(module, catch_up):
    student = os.path.join(LAB_DIR, "defenses", f"{module}.py")
    solution = os.path.join(LAB_DIR, "defenses", "_solutions", f"{module}.py")
    bak = student + ".bak"
    if catch_up:
        if not os.path.exists(bak):
            shutil.copy2(student, bak)
        shutil.copy2(solution, student)
        print(f"[catch-up] installed reference solution for {module} (your work saved to {module}.py.bak)")
    elif os.path.exists(bak):
        shutil.copy2(bak, student)
        print(f"[restore] testing your {module}.py (reference backup kept at {module}.py.bak)")


def reset(base):
    requests.post(f"{base}/lab/reset", timeout=5)


def decisions(base, round_, actors):
    rows = requests.get(f"{base}/lab/decisions?round={round_}", timeout=5).json()
    return [r for r in rows if r["actor"] in actors]


def tally(rows):
    t = {}
    for r in rows:
        t[r["outcome"]] = t.get(r["outcome"], 0) + 1
    return t


def run(round_, catch_up=False, base=BASE_URL):
    require_local(base)
    try:
        requests.get(f"{base}/whoami", timeout=3)
    except Exception:
        raise SystemExit(f"Demo store not reachable at {base}. Start it: python demo_site/app.py")

    module, attack_mod, kwargs, label, bot_eps = ROUNDS[round_]
    manage_solution(module, catch_up)

    # Humans first, on a clean store.
    reset(base)
    human_tally = legit_traffic.run_humans(round_, base)

    # Then the attacker, on a clean store.
    reset(base)
    attack = importlib.import_module(attack_mod)
    importlib.reload(attack)
    attack.run(base=base, **kwargs)
    bot_rows = decisions(base, round_, {"bot", "bot2"})
    bot_tally = tally([r for r in bot_rows if r["endpoint"] in bot_eps])
    bot_success = bot_tally.get("allow", 0)

    human_blocked = human_tally.get("block", 0)
    passed = bot_success <= BOT_CEILING[round_] and human_blocked == 0

    print(f"\n=== Round {round_} checkpoint ===")
    print(f"  bots:   {label} = {bot_success}   (ceiling {BOT_CEILING[round_]})   {bot_tally}")
    print(f"  humans: {human_tally}   (blocked legitimate customers = {human_blocked})")
    print(f"  verdict: {'PASS' if passed else 'FAIL'}")
    if not passed:
        if bot_success > BOT_CEILING[round_]:
            print(f"    - attack not stopped: wire the Round {round_} signature in defenses/{module}.py")
        if human_blocked:
            print(f"    - {human_blocked} real customers blocked: your rule is too broad (false positives)")
    return passed


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, choices=[1, 2, 3, 4, 5], required=True)
    ap.add_argument("--catch-up", action="store_true")
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    ok = run(a.round, catch_up=a.catch_up, base=a.url)
    sys.exit(0 if ok else 1)
