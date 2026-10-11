"""Round checkpoint — run at the end of every round, measuring BOTH sides.

For the chosen round it resets the store, runs the legitimate customers (and
records how they fared), resets again and runs the attacker, so each side is
measured against a clean slate. It then prints:

    bots:   what the attacker achieved this round
    humans: how the real customers fared (allowed / challenged / blocked)
    verdict: a round passes when the attack is defeated at this round's signature
             AND no legitimate customer is blocked. A challenge (a held review, a
             puzzle a person can solve, a step-up) is friction, not failure.

Fell behind, or want to see the finished defense?
    python tools/checkpoint.py --round 2 --catch-up   # install the reference solution
    python tools/checkpoint.py --round 2              # restores your work, tests it

Run with the demo store already running (python demo_site/app.py).
"""

from __future__ import annotations

import argparse
import importlib
import os
import re
import shutil
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
sys.path.insert(0, LAB_DIR)
from attacks._common import BASE_URL, require_local  # noqa: E402
from tools import legit_traffic  # noqa: E402


def _attack(name):
    mod = importlib.import_module(f"attacks.{name}")
    return importlib.reload(mod)


# round -> (defense module, attack module, label, metric->dict, passed(metric), show(metric))
ROUNDS = {
    1: ("review_signals", "round1_review_farm", "fake reviews published",
        lambda base: {"value": _attack("round1_review_farm").run(base=base)},
        lambda m: m["value"] <= 3,
        lambda m: f"{m['value']} reviews published (ceiling 3)"),
    2: ("challenge_policy", "round2_llm_solver", "bot accounts created",
        lambda base: {"value": _attack("round2_llm_solver").run(base=base)},
        lambda m: m["value"] <= 2,
        lambda m: f"{m['value']} accounts created (ceiling 2)"),
    3: ("extractor_traps", "round3_llm_extract", "extractor neutralised",
        lambda base: _attack("round3_llm_extract").run(base=base),
        lambda m: m["honeypot_hits"] >= 1 and m["canaries"] >= 1,
        lambda m: (f"harvested {m['harvested']} records, but honeypot pages fetched "
                   f"{m['honeypot_hits']}, canaries carried {m['canaries']}, "
                   f"{m['tokens']} tokens spent")),
    4: ("llm_guard", "round4_injector", "injections reaching customers",
        lambda base: _attack("round4_injector").run(base=base),
        lambda m: m["hits"] == 0,
        lambda m: f"{m['hits']}/{m['total']} injection variants reached a response"),
}


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


def _aria_check(base):
    """Round 3 negative control: any off-screen block must be aria-hidden, or the
    screen-reader cohort would hear the decoys. Returns a warning or ''."""
    html = requests.get(f"{base}/catalog?page=1", headers={"X-Lab-Session": "aria-probe"}, timeout=10).text
    offscreen = re.findall(r'<div class="[^"]+"([^>]*)>', html)
    for attrs in offscreen:
        if "left: -10000px" in html and 'aria-hidden="true"' not in html:
            return "off-screen content is NOT aria-hidden: screen readers would read your decoys"
    return ""


def run(round_, catch_up=False, base=BASE_URL):
    require_local(base)
    try:
        requests.get(f"{base}/whoami", timeout=3)
    except Exception:
        raise SystemExit(f"Demo store not reachable at {base}. Start it: python demo_site/app.py")

    module, _attack_mod, label, attack_fn, passed_fn, show_fn = ROUNDS[round_]
    manage_solution(module, catch_up)

    # Humans first, on a clean store; capture their tally before the attacker runs.
    reset(base)
    human_tally = legit_traffic.run_humans(round_, base)

    # Then the attacker, on a clean store.
    reset(base)
    metric = attack_fn(base)

    human_blocked = human_tally.get("block", 0)
    attack_defeated = passed_fn(metric)
    passed = attack_defeated and human_blocked == 0

    print(f"\n=== Round {round_} checkpoint ===")
    print(f"  bots:   {label}: {show_fn(metric)}")
    print(f"  humans: {human_tally}   (blocked legitimate customers = {human_blocked})")
    if round_ == 3:
        warn = _aria_check(base)
        if warn:
            print(f"  WARNING: {warn}")
    print(f"  verdict: {'PASS' if passed else 'FAIL'}")
    if not passed:
        if not attack_defeated:
            print(f"    - attack not defeated: wire the Round {round_} signal in defenses/{module}.py")
        if human_blocked:
            print(f"    - {human_blocked} real customers blocked: your rule is too broad (false positives)")
    return passed


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, choices=[1, 2, 3, 4], required=True)
    ap.add_argument("--catch-up", action="store_true")
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    ok = run(a.round, catch_up=a.catch_up, base=a.url)
    sys.exit(0 if ok else 1)
