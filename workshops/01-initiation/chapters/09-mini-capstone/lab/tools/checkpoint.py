"""
W1 Ch9 — Round checkpoint: are you where you should be?

1. Checks that the running store has the round's layers wired
   (defenses/pipeline.py).
2. Runs one drop per key wave: the wave this round must STOP, and the
   wave that BEATS this round (the reason the next round exists).
3. Checks the shoppers: only the expected personas may be stopped by a
   defense. Anything else is a false positive you introduced.

Fell behind? Install the reference pipeline for the round, restart the
store, and run the checkpoint again:
    python tools/checkpoint.py --round 3 --apply
    (Ctrl+C the store, then: python demo_site/app.py)
    python tools/checkpoint.py --round 3

Options:
    --all            run every wave up to the next one, not just the two key waves
    --skip-browser   skip waves 3 and 4 (no Chromium)
"""

import argparse
import os
import shutil
import sys

from drop import BROWSER_WAVES, FALSE_POSITIVE, print_scoreboard, run_drop
from labnet import wait_for_store

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
BASE_LAYERS = ["rate_limit.check", "headers.check"]

EXPECTED = {
    # round: (layers, challenge_enabled, purchases_per_session, {wave: expectation}, personas a defense may stop)
    0: ([], False, None, {0: "wins"}, set()),
    1: (BASE_LAYERS, False, None, {0: "stopped", 1: "wins"}, set()),
    2: (BASE_LAYERS + ["ip_reputation.check"], False, None, {1: "stopped", 2: "wins"}, {"consumer_vpn"}),
    3: (BASE_LAYERS + ["ip_reputation.check", "traps.check", "session_guard.check"], False, None,
        {2: "stopped", 3: "wins"}, {"consumer_vpn"}),
    4: (BASE_LAYERS + ["ip_reputation.check", "traps.check", "session_guard.check", "session_guard.check_binding"],
        True, 1, {3: "capped", 4: "some"}, {"no_js"}),
}
# Bot share of the 20 hoodies that counts as each expectation
# "capped": wave 3 mints 6 sessions, and from Round 4 each one buys at most one hoodie
THRESHOLDS = {"wins": lambda n: n >= 10, "stopped": lambda n: n <= 4, "capped": lambda n: n <= 6,
              "some": lambda n: n >= 1}
DESCRIBE = {"wins": "takes ≥10 of 20", "stopped": "gets ≤4 of 20", "capped": "gets ≤6 of 20 (one per minted session)",
            "some": "still gets a few"}


def apply(round_no):
    target = os.path.join(LAB, "defenses", "pipeline.py")
    backup = target + ".bak"
    shutil.copy(target, backup)
    shutil.copy(os.path.join(LAB, "tools", "solutions", f"pipeline_round{round_no}.py"), target)
    print(f"Installed the reference pipeline for Round {round_no} (your version: defenses/pipeline.py.bak).")
    print("Restart the store (Ctrl+C, then python demo_site/app.py), then run:")
    print(f"    python tools/checkpoint.py --round {round_no}")


def check_config(round_no, config):
    layers, challenge, cap, _, _ = EXPECTED[round_no]
    problems = []
    missing = set(layers) - set(config["layers"])
    extra = set(config["layers"]) - set(layers)
    if missing:
        problems.append(f"missing layers: {', '.join(sorted(missing))}")
    if extra:
        problems.append(f"layers from a later round: {', '.join(sorted(extra))}")
    if config["layers"] and config["layers"][0] != "rate_limit.check":
        problems.append("rate_limit.check should run first (it is the cheapest)")
    if config["challenge_enabled"] != challenge:
        problems.append(f"CHALLENGE_ENABLED should be {challenge}")
    if config["purchases_per_session"] != cap:
        problems.append(f"PURCHASES_PER_SESSION should be {cap}")
    return problems


def main():
    parser = argparse.ArgumentParser(description="Check a round of the W1 Ch9 lab.")
    parser.add_argument("--round", type=int, required=True, choices=sorted(EXPECTED))
    parser.add_argument("--apply", action="store_true", help="install the reference pipeline for this round")
    parser.add_argument("--all", action="store_true", help="run every wave up to the next one")
    parser.add_argument("--skip-browser", action="store_true", help="skip waves 3 and 4")
    args = parser.parse_args()

    if args.apply:
        apply(args.round)
        return 0

    _, _, _, key_waves, allowed_fp = EXPECTED[args.round]
    config = wait_for_store()["pipeline"]
    print(f"=== Checkpoint: Round {args.round} ===\n")
    problems = check_config(args.round, config)
    if problems:
        print("❌ defenses/pipeline.py doesn't match this round:")
        for p in problems:
            print(f"     - {p}")
        print(f"\n   Fix it and restart the store, or: python tools/checkpoint.py --round {args.round} --apply")
        return 1
    print(f"✅ pipeline: {', '.join(config['layers']) or 'no layers'}"
          f"{' + proof of work + 1 per session' if config['challenge_enabled'] else ''}\n")

    waves = dict(key_waves)
    if args.all:
        for w in range(0, max(key_waves) + 1):
            waves.setdefault(w, "stopped")
    failures = 0
    for wave, expectation in sorted(waves.items()):
        if args.skip_browser and wave in BROWSER_WAVES:
            print(f"⏭️  wave {wave}: skipped (--skip-browser)\n")
            continue
        result = run_drop([wave])
        print_scoreboard(result)
        bot_units = result["sold"].get(f"wave{wave}", 0)
        hurt = {h["persona"] for h in result["humans"] if h["outcome"] in FALSE_POSITIVE or h["outcome"] == "error"}
        ok_bots = THRESHOLDS[expectation](bot_units)
        ok_humans = hurt <= allowed_fp
        failures += (not ok_bots) + (not ok_humans)
        print(f"{'✅' if ok_bots else '❌'} wave {wave} {DESCRIBE[expectation]}: got {bot_units}")
        if ok_humans:
            note = f" (expected: {', '.join(sorted(allowed_fp))})" if hurt else ""
            print(f"✅ shoppers stopped by a defense: {', '.join(sorted(hurt)) or 'none'}{note}\n")
        else:
            print(f"❌ unexpected false positives: {', '.join(sorted(hurt - allowed_fp))}\n")

    if failures:
        print(f"❌ {failures} check(s) differ from the expected results. Compare with the "
              f"reference: tools/solutions/pipeline_round{args.round}.py and defenses/policy.py.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
