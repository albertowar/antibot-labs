"""
W2 Ch1 — Round Checkpoint (Section 1.6)

Run at the end of every round to check you are where you should be, and to
measure BOTH sides of the defense:

  - your code:     the function you wrote this round, against known inputs
  - bot traffic:   every attack introduced so far vs. the expected result
  - real users:    replayed real-browser profiles (tools/legit_traffic.py)
  - defender cost: sensor scoring time, collection time, script size

Fell behind? One command installs the reference solution for every round up
to N (your files are kept as *.bak), then restart the demo site:

    python tools/checkpoint.py --round 3 --catch-up
    cd demo_site && DEFENSE_LEVEL=3 python app.py

Run:
    python tools/checkpoint.py --round 3
    python tools/checkpoint.py --round 3 --skip-browser   # no browser attacks
"""

import argparse
import filecmp
import importlib
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFENSES = os.path.join(HERE, "..", "defenses")
sys.path.insert(0, DEFENSES)

import scoreboard  # noqa: E402  (also puts attacks/ on sys.path)
import legit_traffic  # noqa: E402

# Round -> the defense module you edit in that round
ROUND_MODULES = {1: "automation_artifacts", 2: "consistency", 3: "lie_detection", 4: "interaction"}

DESKTOP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
MOBILE_UA = ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36")


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
import labnet  # noqa: E402


def geometry(outer_w, outer_h, inner_w, inner_h):
    return {"outer_w": outer_w, "outer_h": outer_h, "inner_w": inner_w, "inner_h": inner_h}


def realm(ua, languages=("en-US", "en")):
    return {"ua": ua, "platform": "Win32", "languages": list(languages), "hardware_concurrency": 8}


# Round -> (function name, [(description, input, should_score_points)])
UNIT_CHECKS = {
    1: ("check_webdriver", [
        ("navigator.webdriver true", {"webdriver": True}, True),
        ("navigator.webdriver false", {"webdriver": False}, False),
        ("navigator.webdriver missing (old Safari)", {"webdriver": None}, False),
    ]),
    2: ("check_headless_shape", [
        ("desktop, outer == viewport", {"ua": DESKTOP_UA, "geometry": geometry(1280, 720, 1280, 720)}, True),
        ("desktop, outer is 0x0", {"ua": DESKTOP_UA, "geometry": geometry(0, 0, 1280, 720)}, True),
        ("desktop window with toolbars", {"ua": DESKTOP_UA, "geometry": geometry(1920, 1032, 1920, 945)}, False),
        ("phone (no outer chrome is normal)", {"ua": MOBILE_UA, "geometry": geometry(412, 915, 412, 915)}, False),
    ]),
    3: ("check_realm_consistency", [
        ("Worker UA differs", {**realm(DESKTOP_UA), "webdriver": False,
                               "worker": realm(DESKTOP_UA.replace("Chrome/", "HeadlessChrome/"))}, True),
        ("Worker languages differ", {**realm(DESKTOP_UA), "webdriver": False,
                                     "worker": realm(DESKTOP_UA, ("en-US",))}, True),
        ("iframe UA differs", {**realm(DESKTOP_UA), "webdriver": False, "worker": realm(DESKTOP_UA),
                               "iframe": {"ua": "x", "platform": "Win32", "webdriver": False}}, True),
        ("all realms agree", {**realm(DESKTOP_UA), "webdriver": False, "worker": realm(DESKTOP_UA),
                              "iframe": {"ua": DESKTOP_UA, "platform": "Win32", "webdriver": False}}, False),
        ("Worker blocked (CSP)", {**realm(DESKTOP_UA), "webdriver": False, "worker": {"error": "timeout"}}, False),
    ]),
    4: ("check_teleport", [
        ("1 pointer move before the click", {"moves_before": 1}, True),
        ("0 pointer moves", {"moves_before": 0}, True),
        ("57 pointer moves", {"moves_before": 57}, False),
    ]),
}


def catch_up(round_number):
    """Install the reference solutions for rounds 1..round_number (each of your files is kept once as .bak)."""
    installed = labnet.catch_up(os.path.join(HERE, '..'), round_number)
    for f in installed:
        print(f"  installed solutions -> {f}   (your version kept as {f}.bak; --restore puts it back)")
    if not installed:
        print("  nothing to install up to this round")
    level = min(round_number, 4)
    print(f"\nRestart the demo site:  cd demo_site && DEFENSE_LEVEL={level} python app.py")


def check_student_code(round_number):
    failures = 0
    for rnd in range(1, min(round_number, 4) + 1):
        module = importlib.import_module(ROUND_MODULES[rnd])
        func_name, cases = UNIT_CHECKS[rnd]
        func = getattr(module, func_name)
        round_failures = 0
        for description, data, should_fire in cases:
            points, _ = func(data)
            ok = (points > 0) == should_fire
            round_failures += not ok
            if not ok:
                want = "points" if should_fire else "0 points"
                print(f"  ❌ {ROUND_MODULES[rnd]}.{func_name}: {description}: expected {want}, got {points}")
        if not round_failures:
            print(f"  ✅ {ROUND_MODULES[rnd]}.{func_name} (Round {rnd})")
        failures += round_failures
    if failures:
        print(f"     Finish the TODO (Round {min(round_number, 4)}) or run with --catch-up.")
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--round", type=int, required="--restore" not in sys.argv, choices=range(0, 6))
    parser.add_argument("--skip-browser", action="store_true", help="skip browser-based attacks")
    parser.add_argument("--catch-up", action="store_true", help="install the reference solutions up to this round")
    parser.add_argument("--restore", action="store_true", help="put your .bak files back, then exit")
    args = parser.parse_args()
    if args.restore:
        restored = labnet.restore(os.path.join(HERE, '..'))
        print("restored: " + (", ".join(restored) or "nothing to restore (no .bak files)"))
        return 0

    if args.catch_up:
        catch_up(args.round)
        return 0

    expected_level = min(args.round, 4)
    try:
        level = scoreboard.server_level()
    except OSError:
        print(f"❌ Demo site not reachable on {scoreboard.BASE_URL}. Is it running?")
        return 1
    print(f"=== Checkpoint: Round {args.round} (server at DEFENSE_LEVEL={level}) ===\n")
    if level != expected_level:
        print(f"❌ Expected DEFENSE_LEVEL={expected_level}. Restart the demo site with:")
        print(f"     cd demo_site && DEFENSE_LEVEL={expected_level} python app.py")
        return 1

    failures = 0
    if args.round >= 1:
        print("Your code")
        failures += check_student_code(args.round)
        print()

    print("Bot traffic")
    attacks = [a for a in scoreboard.ATTACKS if a[3] <= args.round]
    rows = scoreboard.measure_attacks(level, attacks, args.skip_browser)
    scoreboard.print_attacks(rows)
    failures += sum(1 for r in rows if not r.get("skipped") and not scoreboard.attack_ok(r))

    print("\nReal users (replayed profiles)")
    results = legit_traffic.run(scoreboard.BASE_URL)
    failures += len(scoreboard.print_legit(results))

    print("\nDefender cost")
    scoreboard.print_cost(results)

    print()
    if failures:
        print(f"❌ {failures} check(s) differ from the expected results. "
              f"Compare with the expected-results table in README.md, or run: python tools/checkpoint.py --round {args.round} --catch-up")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
