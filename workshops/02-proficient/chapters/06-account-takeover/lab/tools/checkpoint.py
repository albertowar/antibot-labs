"""Per-round checkpoint: run the round's attacks + the human simulator, score both,
and compare against the expected results so a learner who fell behind can confirm
they are caught up.

Each round runs the new attack *and* the previous round's attack, to show the old
attack is now defeated and the new one wins — the arms-race structure of the whole
chapter, in one command.

Usage (demo store running at the matching DEFENSE_LEVEL):
    python tools/checkpoint.py --round 2
    python tools/checkpoint.py --round 2 --catch-up   # prints the reference-solution command
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import os
import sys
import time

import httpx

sys.path.insert(0, os.path.dirname(__file__))
from _paths import ATTACKS, BASE_URL  # noqa: E402
import scoreboard  # noqa: E402
import legit_traffic  # noqa: E402

# Which attacks each round runs: (previous-now-defeated, this-round's-new-attack).
ROUND_ATTACKS = {
    0: ["round0_naive_stuffer"],
    1: ["round0_naive_stuffer", "round1_distributed_stuffer"],
    2: ["round1_distributed_stuffer", "round2_clean_list_stuffer"],
    3: ["round2_clean_list_stuffer", "round3_stealer_log_replay"],
    4: ["round3_stealer_log_replay", "round4_session_replay"],
}


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
import labnet  # noqa: E402

LAB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def load_attack(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ATTACKS, f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, ATTACKS)
    spec.loader.exec_module(mod)
    return mod


def server_state():
    return httpx.get(f"{BASE_URL}/lab/info", timeout=5).json()


def check_expectations(round_no, results, legit):
    """Return a list of (ok, message). Ranges absorb the small attack randomness."""
    checks = []

    def ato(name):
        return results[name].get("accounts_taken_over", 0)

    if round_no == 0:
        checks.append((ato("round0_naive_stuffer") >= 38,
                       f"naive stuffer takes over ~40 accounts (got {ato('round0_naive_stuffer')})"))
        checks.append((legit["blocked_false_positive"] == 0,
                       f"no real users blocked (got {legit['blocked_false_positive']})"))
    elif round_no == 1:
        checks.append((ato("round0_naive_stuffer") <= 3,
                       f"naive stuffer now throttled to ~0 (got {ato('round0_naive_stuffer')})"))
        checks.append((ato("round1_distributed_stuffer") >= 35,
                       f"distributed stuffer still wins (got {ato('round1_distributed_stuffer')})"))
        checks.append((2 <= legit["blocked_false_positive"] <= 9,
                       f"CGNAT cohort pays a cost (blocked={legit['blocked_false_positive']})"))
    elif round_no == 2:
        checks.append((ato("round1_distributed_stuffer") <= 3,
                       f"distributed stuffer now flagged (got {ato('round1_distributed_stuffer')})"))
        checks.append((ato("round2_clean_list_stuffer") >= 35,
                       f"clean-list stuffer still wins (got {ato('round2_clean_list_stuffer')})"))
    elif round_no == 3:
        checks.append((ato("round2_clean_list_stuffer") == 0,
                       f"clean-list stuffer fully stopped (got {ato('round2_clean_list_stuffer')})"))
        checks.append((ato("round3_stealer_log_replay") >= 9,
                       f"stealer-log replay still wins (got {ato('round3_stealer_log_replay')})"))
        checks.append((legit["friction_stepup"] >= 20,
                       f"breached-password users see step-up (got {legit['friction_stepup']})"))
    elif round_no == 4:
        checks.append((ato("round3_stealer_log_replay") == 0,
                       f"stealer-log login now stepped up (got {ato('round3_stealer_log_replay')})"))
        r4 = results["round4_session_replay"]
        checks.append((r4.get("accounts_read", 0) >= 9,
                       f"stolen cookie still reads the account (got {r4.get('accounts_read', 0)})"))
        checks.append((r4.get("sensitive_actions", 0) == 0,
                       f"sensitive action blocked by re-auth (got {r4.get('sensitive_actions', 0)})"))

    return checks


def catch_up(rnd):
    """Install the reference solutions for rounds 1..rnd (each of your files is kept once as .bak)."""
    installed = labnet.catch_up(LAB_DIR, rnd)
    for f in installed:
        print(f"  installed solutions -> {f}   (your version kept as {f}.bak; --restore puts it back)")
    if not installed:
        print("  nothing to install up to this round")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--round", type=int, required="--restore" not in sys.argv, choices=range(0, 5))
    parser.add_argument("--catch-up", action="store_true",
                        help="install the reference solutions for rounds 1..N (your files are kept as .bak)")
    parser.add_argument("--restore", action="store_true", help="put your .bak files back, then exit")
    args = parser.parse_args()
    if args.restore:
        restored = labnet.restore(LAB_DIR)
        print("restored: " + (", ".join(restored) or "nothing to restore (no .bak files)"))
        return 0

    try:
        state = server_state()
    except httpx.RequestError:
        print(f"❌ Can't reach the demo store at {BASE_URL}. Start it first.")
        return 1

    if args.catch_up:
        catch_up(args.round)
        print(f"ℹ️  Restart the store at DEFENSE_LEVEL={args.round}, then run the checkpoint again without --catch-up.")
        return 0
    if state["level"] != args.round:
        print(f"❌ The demo store is at DEFENSE_LEVEL={state['level']} but this is Round "
              f"{args.round}. Restart it with:\n"
              f"     DEFENSE_LEVEL={args.round} python demo_site/app.py")
        return 1

    httpx.post(f"{BASE_URL}/lab/reset", timeout=10)
    since = time.time()

    results = {}
    for name in ROUND_ATTACKS[args.round]:
        mod = load_attack(name)
        results[name] = asyncio.run(mod.run())

    legit = legit_traffic.run()
    latency = scoreboard.login_latency(since)
    print(scoreboard.render(args.round, state["level"], list(results.values()), legit, latency))
    print()

    checks = check_expectations(args.round, results, legit)
    failed = 0
    for ok, msg in checks:
        print(f"  {'✅' if ok else '❌'} {msg}")
        failed += not ok
    print()
    if failed:
        print(f"❌ Round {args.round}: {failed} check(s) differ from the expected results.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
