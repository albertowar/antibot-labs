"""
Chapter 5 — Round Checkpoint (Section 5.8)

Run at the end of every round to check you are where you should be, and to
measure BOTH sides of the defense:

  - bot traffic:   every attack script vs. the expected result, plus the
                   attacker's throughput (requests/second, incl. start-up)
  - real users:    tools/legit_traffic.py personas, with the documented
                   false positives reported as cost, not hidden
  - defender cost: scoring time per request (Server-Timing)

Fell behind? Restart the demo site with the reference solutions:
    USE_SOLUTIONS=1 DEFENSE_LEVEL=<round> python demo_site/app.py

Run:
    python tools/checkpoint.py --round 2
    python tools/checkpoint.py --round 2 --skip-browser   # no Playwright (faster, no FP data for browsers)
"""

import argparse
import importlib.util
import os
import statistics
import sys
import time

import requests

import legit_traffic
from legit_traffic import EXPECTED_FALSE_POSITIVE_FROM, INFORMATIONAL

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attacks"))
from _lab import BASE_URL, CA_FILE  # noqa: E402

ATTACKS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attacks")

# attack script -> first DEFENSE_LEVEL that blocks it (None: nothing in this chapter does)
FIRST_BLOCKED_AT = {
    "round1_naive_requests": 1,
    "round1_cipher_tweak": 2,
    "round2_impit_chrome": 3,
    "round3_curl_cffi_chrome": 4,
    "round4_playwright_chromium": None,
}
BROWSER_ATTACKS = {"round4_playwright_chromium"}


def load_attack(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ATTACKS_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def server_level():
    return requests.get(f"{BASE_URL}/tls-check", verify=CA_FILE, timeout=5).json()["level"]


def check_bots(level, skip_browser):
    failures = 0
    print("Bot traffic                         blocked   expected        attacker req/s")
    for name, first_blocked in FIRST_BLOCKED_AT.items():
        if name in BROWSER_ATTACKS and skip_browser:
            print(f"  ⏭️  {name:<30} skipped (--skip-browser)")
            continue
        started = time.perf_counter()
        results = load_attack(name).run()
        elapsed = time.perf_counter() - started
        blocked = sum(r["status"] == 403 for r in results)
        should_block = first_blocked is not None and level >= first_blocked
        ok = blocked == (len(results) if should_block else 0)
        failures += not ok
        expectation = "blocked" if should_block else "gets through"
        print(f"  {'✅' if ok else '❌'} {name:<30} {blocked:>2}/{len(results):<5} {expectation:<15} "
              f"{len(results) / elapsed:7.1f}")
        if not ok and results and results[0]["reasons"]:
            print(f"       {results[0]['reasons']}")
    return failures


def check_users(level, skip_browser):
    failures = 0
    rows = legit_traffic.run(browsers=not skip_browser)
    print("\nReal users                          blocked")
    for persona in dict.fromkeys(r["persona"] for r in rows):
        mine = [r for r in rows if r["persona"] == persona]
        if mine[0]["status"] is None:
            print(f"  ⏭️  {persona:<30} {mine[0]['reasons'][0]}")
            continue
        blocked = [r for r in mine if r["status"] == 403]
        if not blocked:
            print(f"  ✅ {persona:<30} 0/{len(mine)}")
            continue
        why = blocked[0]["reasons"]
        if persona in INFORMATIONAL:
            print(f"  ⚠️  {persona:<30} {len(blocked)}/{len(mine)}  informational: {why}")
        elif level >= EXPECTED_FALSE_POSITIVE_FROM.get(persona, 99):
            print(f"  ⚠️  {persona:<30} {len(blocked)}/{len(mine)}  documented false positive: {why}")
        else:
            failures += 1
            print(f"  ❌ {persona:<30} {len(blocked)}/{len(mine)}  unexpected: {why}")
    counted = [r for r in rows if r["status"] is not None and r["persona"] not in INFORMATIONAL]
    total_fp = sum(r["status"] == 403 for r in counted)
    print(f"  → real-user requests blocked: {total_fp}/{len(counted)}")

    timings = [r["score_ms"] for r in rows if r["score_ms"] is not None]
    if len(timings) >= 2:
        p95 = statistics.quantiles(timings, n=20)[-1]
        print(f"\nDefender cost\n  TLS scoring: median {statistics.median(timings):.2f} ms, p95 {p95:.2f} ms per request")
    return failures


def main():
    parser = argparse.ArgumentParser(description="Chapter 5 round checkpoint")
    parser.add_argument("--round", type=int, required=True, choices=range(0, 5))
    parser.add_argument("--skip-browser", action="store_true", help="skip Playwright attack and personas")
    args = parser.parse_args()

    try:
        level = server_level()
    except requests.RequestException:
        print(f"❌ Edge not reachable on {BASE_URL}. Are tools/edge.py and demo_site/app.py running?")
        return 1
    print(f"=== Checkpoint: Round {args.round} (server at DEFENSE_LEVEL={level}) ===\n")
    if level != args.round:
        print(f"❌ Expected DEFENSE_LEVEL={args.round}. Restart the demo site with:")
        print(f"     DEFENSE_LEVEL={args.round} python demo_site/app.py")
        return 1

    failures = check_bots(level, args.skip_browser) + check_users(level, args.skip_browser)
    print()
    if failures:
        print(f"❌ {failures} check(s) differ from the expected results.")
        print(f"   Fell behind? USE_SOLUTIONS=1 DEFENSE_LEVEL={args.round} python demo_site/app.py")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
