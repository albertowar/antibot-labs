"""
Chapter 7 — Round Checkpoint (Section 7.7)

Run at the end of every round to check you are where you should be, and to
measure BOTH sides of the defense:

  - bot traffic:   every attack script: pages scraped, and what they cost the bot
  - real users:    simulated devices (tools/legit_traffic.py): blocked, wait, give-up
  - defender cost: gate and verify time per request (Server-Timing), store ops

PoW rarely *blocks* a paying bot, so the bot table reports price as well
as success: CPU-seconds and dollars per 1,000 pages.

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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "attacks"))
from _common import BASE_URL, USD_PER_VCPU_HOUR  # noqa: E402

ATTACKS_DIR = os.path.join(os.path.dirname(__file__), "..", "attacks")

# attack -> expected outcome at DEFENSE_LEVEL 0..4
#   full: >= 95% of pages · partial: some pages, < 50% · blocked: no pages
EXPECTED = {
    "round1_naive_scraper":      ["full", "blocked", "blocked", "blocked", "blocked"],
    "round1_forge_difficulty":   ["full", "full", "blocked", "blocked", "blocked"],
    "round2_solve_once_replay":  ["full", "full", "full", "partial", "partial"],
    "round3_solver_pool":        ["full", "full", "full", "full", "full"],
    "round4_distributed":        ["full", "full", "full", "full", "full"],
    "round5_playwright_browser": ["full", "full", "full", "full", "full"],
}
# At level 4 the price matters more than success: (attack, check, description)
LEVEL4_PRICE_CHECKS = [
    ("round3_solver_pool", lambda r: (r["max_bits"] or 0) >= 20, "difficulty climbs to ≥ 20 bits"),
    ("round4_distributed", lambda r: r["max_bits"] == 16, "every identity stays at 16 bits"),
]


def load_attack(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ATTACKS_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def server_state():
    with urllib.request.urlopen(f"{BASE_URL}/pow-check", timeout=5) as r:
        return json.loads(r.read())


def reset_server():
    req = urllib.request.Request(f"{BASE_URL}/lab/reset", method="POST")
    urllib.request.urlopen(req, timeout=5).close()


def outcome(result):
    if result["pages_ok"] == 0:
        return "blocked"
    if result["success"] >= 0.95:
        return "full"
    return "partial" if result["success"] < 0.5 else "most"


def fmt_cost(r):
    if r["cpu_s_per_1k"] is None or r["solves"] == 0:
        return "-"
    return f"{r['cpu_s_per_1k']:7.2f} CPU-s  ${r['usd_per_1k']:.6f}"


def browser_available():
    return importlib.util.find_spec("playwright") is not None


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--round", type=int, required=True, choices=range(0, 6))
    parser.add_argument("--skip-browser", action="store_true", help="skip the Playwright attack")
    args = parser.parse_args()
    expected_level = min(args.round, 4)

    try:
        state = server_state()
    except OSError:
        print(f"❌ Demo site not reachable on {BASE_URL}. Is it running?")
        return 1
    level = state["level"]
    print(f"=== Checkpoint: Round {args.round} "
          f"(server at DEFENSE_LEVEL={level}, {state['store']}) ===\n")
    if level != expected_level:
        print(f"❌ Expected DEFENSE_LEVEL={expected_level}. Restart the demo site with:")
        print(f"     cd demo_site && DEFENSE_LEVEL={expected_level} python app.py")
        return 1
    reset_server()  # fresh rate windows, budgets and spent nonces: comparable runs

    failures = 0

    print("Real users (simulated devices, "
          f"desktop {legit_traffic.DESKTOP_MHS} MH/s, {legit_traffic.PATIENCE_S:.0f} s patience)")
    legit = legit_traffic.run()
    for row in legit:
        if row["profile"] == "no_js_reader" and row["blocked"]:
            mark, note = "⚠️ ", "  (the price of any JS-only gate)"
        elif row["blocked"]:
            mark, note = "❌", ""
            failures += 1
        elif row["give_up"] >= 0.2:
            expected_fp = level >= 4 and row["profile"] == "cgnat_neighbour"
            mark = "⚠️ " if expected_fp else "❌"
            note = "  (false positive: shares an IP with busy neighbours)" if expected_fp else ""
            failures += not expected_fp
        else:
            mark, note = "✅", ""
        print(f"  {mark} {row['profile']:<16} {legit_traffic.describe(row)}{note}")

    print("\nBot traffic                          pages     solves  bits      price per 1,000 pages")
    by_name = {}
    for name, expectations in EXPECTED.items():
        if name.startswith("round5") and (args.skip_browser or not browser_available()):
            why = "--skip-browser" if args.skip_browser else "playwright not installed"
            print(f"  ⏭️  {name:<31} skipped ({why})")
            continue
        result = load_attack(name).run()
        by_name[name] = result
        got, want = outcome(result), expectations[level]
        ok = got == want
        failures += not ok
        bits = ",".join(str(b) for b in sorted(set(result["bits"]))) or "-"
        print(f"  {'✅' if ok else '❌'} {name:<31} {result['pages_ok']:>3}/{result['pages_wanted']:<4}  "
              f"{result['solves']:>5}   {bits:<8}  {fmt_cost(result)}"
              f"{'' if ok else f'   (expected: {want}, got: {got})'}")
        if not ok and result["notes"]:
            print(f"       {result['notes'][-1]}")

    if level >= 4:
        print("\nPrice checks (level 4)")
        for name, check, description in LEVEL4_PRICE_CHECKS:
            if name in by_name:
                ok = check(by_name[name])
                failures += not ok
                print(f"  {'✅' if ok else '❌'} {name}: {description} "
                      f"(saw {sorted(set(by_name[name]['bits']))})")

    gate = [ms for r in legit for ms in r["gate_ms"] if ms is not None]
    verify = [ms for r in legit for ms in r["verify_ms"] if ms is not None]
    ops = [o for r in legit for o in r["ops"] if o is not None]
    if gate:
        print("\nDefender cost")
        line = f"  pass check: median {statistics.median(gate) * 1000:.0f} µs"
        if verify:
            line += f" · verify: median {statistics.median(verify) * 1000:.0f} µs"
        if ops:
            line += f" · store ops per page: {statistics.median(ops):.0f}"
        print(line)
    print(f"  (bot prices assume ${USD_PER_VCPU_HOUR} per vCPU-hour)")

    print()
    if failures:
        print(f"❌ {failures} check(s) differ from the expected results. Ask your instructor.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
