"""
Chapter 4 — Round Checkpoint (Section 4.7)

Run at the end of every round to check you are where you should be, and to
measure BOTH sides of the defense:

  - bot traffic:   every attack script, blocked or not, vs. the expected result
  - real users:    replayed real-browser profiles (tools/legit_traffic.py)
  - defender cost: header-scoring time per request (Server-Timing)

Fell behind? The defenses are already written; catching up means restarting
the demo site with the round's level:
    cd demo_site && DEFENSE_LEVEL=<round> python app.py

Run:
    python tools/checkpoint.py --round 3
    python tools/checkpoint.py --round 3 --skip-browser   # skip the Playwright attack
"""

import argparse
import importlib.util
import json
import os
import statistics
import sys
import urllib.request

import legit_traffic

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

ATTACKS_DIR = os.path.join(os.path.dirname(__file__), "..", "attacks")

# attack script -> first DEFENSE_LEVEL that blocks it
FIRST_BLOCKED_AT = {
    "round1_naive_requests": 1,
    "round2_fake_ua": 2,
    "round3_devtools_copy": 3,
    "round4_client_hints_spoof": 4,
    "round5_playwright_ua_override": 3,
}
SCRAPE_PATH = "/api/products"


def load_attack(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ATTACKS_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def server_level():
    with urllib.request.urlopen(f"{BASE_URL}/header-check", timeout=5) as r:
        return json.loads(r.read())["level"]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--round", type=int, required=True, choices=range(0, 6))
    parser.add_argument("--skip-browser", action="store_true", help="skip the Playwright attack")
    args = parser.parse_args()

    expected_level = min(args.round, 4)
    try:
        level = server_level()
    except OSError:
        print(f"❌ Demo site not reachable on {BASE_URL}. Is it running?")
        return 1
    print(f"=== Checkpoint: Round {args.round} (server at DEFENSE_LEVEL={level}) ===\n")
    if level != expected_level:
        print(f"❌ Expected DEFENSE_LEVEL={expected_level}. Restart the demo site with:")
        print(f"     cd demo_site && DEFENSE_LEVEL={expected_level} python app.py")
        return 1

    failures = 0

    print("Bot traffic")
    for name, first_blocked in FIRST_BLOCKED_AT.items():
        if name.startswith("round5") and args.skip_browser:
            print(f"  ⏭️  {name:<32} skipped (--skip-browser)")
            continue
        results = [r for r in load_attack(name).run() if r["path"] == SCRAPE_PATH]
        blocked = sum(r["status"] == 403 for r in results)
        is_blocked = blocked == len(results)
        should_block = level >= first_blocked
        ok = is_blocked == should_block
        failures += not ok
        expectation = "blocked" if should_block else "gets through"
        print(f"  {'✅' if ok else '❌'} {name:<32} {blocked}/{len(results)} blocked "
              f"(expected: {expectation})")

    print("\nReal users (replayed browser profiles)")
    legit = legit_traffic.run()
    blocked = [r for r in legit if r["status"] == 403]
    suspicious = {r["profile"] for r in legit if r["verdict"] == "suspicious"}
    failures += bool(blocked)
    print(f"  {'✅' if not blocked else '❌'} {len(blocked)}/{len(legit)} requests blocked "
          f"across {len({r['profile'] for r in legit})} profiles")
    for r in blocked:
        print(f"       {r['profile']} GET {r['path']}: {r['reasons']}")
    if suspicious:
        print(f"  ⚠️  scored 'suspicious': {', '.join(sorted(suspicious))}")

    timings = [r["score_ms"] for r in legit if r["score_ms"] is not None]
    if timings:
        p95 = statistics.quantiles(timings, n=20)[-1] if len(timings) >= 2 else timings[0]
        print("\nDefender cost")
        print(f"  header scoring: median {statistics.median(timings):.2f} ms, "
              f"p95 {p95:.2f} ms per request")

    print()
    if failures:
        print(f"❌ {failures} check(s) differ from the expected results. Ask your instructor.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
