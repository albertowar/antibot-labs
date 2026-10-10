"""
Chapter 2 — Round Checkpoint (Section 2.7)

Run at the end of every round to check you are where you should be, and to
measure BOTH sides of the defense:

  - bot traffic:   every attack introduced so far, vs. the expected result
  - real users:    real browser engines browsing the store (tools/legit_traffic.py)
  - defender cost: gate/verify time (Server-Timing) and challenge script size
  - attacker cost: time and browser solves per 1,000 pages

Fell behind? Every defense is already written. Catching up means restarting
the demo site with the round's level:
    cd demo_site && DEFENSE_LEVEL=<round> python app.py

Run:
    python tools/checkpoint.py --round 3
    python tools/checkpoint.py --round 3 --skip-browser   # no Playwright (no FP measurement!)
"""

import argparse
import importlib.util
import json
import os
import statistics
import sys
import urllib.request

import legit_traffic

BASE_URL = os.environ.get("DEMO_URL", "http://localhost:5000")
ATTACKS_DIR = os.path.join(os.path.dirname(__file__), "..", "attacks")
sys.path.insert(0, ATTACKS_DIR)

# attack -> (round it is introduced in, first DEFENSE_LEVEL that stops it)
ATTACKS = {
    "round1_requests_scraper": (0, 1),
    "round1_cookie_forge": (1, 2),
    "round2_python_port": (2, 3),
    "round3_jsdom_solver": (3, 4),
    "round4_playwright_harvest": (4, 5),
    "round5_resolve_loop": (5, None),
}
BROWSER_ATTACKS = {"round4_playwright_harvest", "round5_resolve_loop"}


def load_attack(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ATTACKS_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def get(path, method="GET"):
    req = urllib.request.Request(f"{BASE_URL}{path}", method=method)
    try:
        r = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as e:
        r = e
    return r.status, r.headers, r.read()


def server_level():
    return json.loads(get("/challenge-check")[2])["level"]


def script_bytes(level):
    if level < 2:
        return None
    status, headers, body = get("/", method="GET")
    sid = headers.get("Set-Cookie", "").split(";")[0]
    req = urllib.request.Request(f"{BASE_URL}/challenge/new", method="POST", headers={"Cookie": sid})
    ch = json.loads(urllib.request.urlopen(req, timeout=5).read())
    return len(get(ch["script"])[2])


def run_attacks(level, skip_browser):
    """Run each attack that exists by this round. Returns (results, failures)."""
    results, failures = [], 0
    for name, (introduced, stopped_at) in ATTACKS.items():
        if introduced > level:
            continue
        if name in BROWSER_ATTACKS and skip_browser:
            print(f"  ⏭️  {name:<28} skipped (--skip-browser)")
            continue
        r = load_attack(name).run()
        results.append(r)
        got_all = r["pages_ok"] == r["pages_total"]
        should_pass = stopped_at is None or level < stopped_at
        ok = got_all == should_pass
        failures += not ok
        expectation = "gets through" if should_pass else "stopped"
        cost = f", {r['solves']} solve(s)" if r["solves"] else ""
        print(f"  {'✅' if ok else '❌'} {name:<28} {r['pages_ok']:>3}/{r['pages_total']} pages "
              f"in {r['seconds']:.1f} s{cost}  (expected: {expectation})")
        if r["reason"] and r["pages_ok"] < r["pages_total"]:
            print(f"       {r['reason']}")
    return results, failures


def main():
    parser = argparse.ArgumentParser(description="Chapter 2 round checkpoint")
    parser.add_argument("--round", type=int, required=True, choices=range(0, 6))
    parser.add_argument("--skip-browser", action="store_true",
                        help="skip Playwright attacks and the real-user simulation")
    args = parser.parse_args()

    try:
        level = server_level()
    except OSError:
        print(f"❌ Demo site not reachable on {BASE_URL}. Is it running?")
        return 1
    print(f"=== Checkpoint: Round {args.round} (server at DEFENSE_LEVEL={level}) ===\n")
    if level != args.round:
        print(f"❌ Expected DEFENSE_LEVEL={args.round}. Restart the demo site with:")
        print(f"     cd demo_site && DEFENSE_LEVEL={args.round} python app.py")
        return 1

    print("Bot traffic")
    results, failures = run_attacks(level, args.skip_browser)

    print("\nReal users (real browser engines)")
    if args.skip_browser:
        print("  ⏭️  skipped: false positives NOT measured this run")
    else:
        legit = legit_traffic.run()
        legit_traffic.print_report(legit)
        hurt = [r for r in legit if not r["nojs"]
                and (r["pages_ok"] < r["pages_total"] or r["challenges_failed"])]
        failures += bool(hurt)
        nojs = [r for r in legit if r["nojs"]]
        if nojs and level >= 1:
            print("  ⚠️  no-JS users are blocked by design: what do they get instead? (policy, not a bug)")

    print("\nCost")
    cleared = [r["gate_ms"] for r in results if r["gate_ms"] is not None]
    if cleared:
        print(f"  defender: gate {statistics.median(cleared):.3f} ms per cleared request "
              f"(median, Server-Timing)")
    size = script_bytes(level)
    if size:
        print(f"  client:   challenge script {size / 1024:.1f} KB")
    for r in results:
        if r["solves"] and r["pages_ok"]:
            per_1k = r["solves"] / r["pages_ok"] * 1000
            print(f"  attacker: {r['attack']:<28} {per_1k:5.1f} solves per 1,000 pages "
                  f"({r['solve_seconds']:.2f} s solving)")

    print()
    if failures:
        print(f"❌ {failures} check(s) differ from the expected results. Ask your instructor.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
