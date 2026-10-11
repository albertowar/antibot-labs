"""
Chapter 3: round checkpoint (Section 3.7).

Run at the end of every round to check you are where you should be, and to
measure BOTH sides of the defense:

  - bot traffic:   every attack script vs. what should happen at this level
  - real users:    40 fresh synthetic humans (tools/humans.py), plus YOUR
                   recorded traces (tools/traces/*.json, "source": "browser")
                   scored offline. Blocked = false positive; challenged = friction
  - defender cost: scoring time per request (Server-Timing) and telemetry
                   size per session

Fell behind? Every defense is already written; catching up means restarting
the demo site with the round's level:
    DEFENSE_LEVEL=<round> python demo_site/app.py

Run:
    python tools/checkpoint.py --round 3
    python tools/checkpoint.py --round 3 --skip-browser    # no Playwright attacks
"""

import argparse
import glob
import importlib.util
import json
import os
import statistics
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ATTACKS = os.path.join(HERE, "..", "attacks")
sys.path[:0] = [ATTACKS, os.path.join(HERE, "..", "defenses")]

import humans                       # noqa: E402
from scoring import score_offline   # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

# (label, module, kwargs, first level that stops it, runs, how many must be stopped there)
ATTACKS_PLAN = [
    ("round1_click_fill", "round1_click_fill", {}, 1, 1, 1),
    ("round2_linear_steps", "round2_linear_steps", {}, 2, 1, 1),
    ("round3_humanizer", "round3_humanizer", {"ease": False, "runs": 2}, 3, 2, 2),
    ("round3_humanizer --ease", "round3_humanizer", {"ease": True, "runs": 2}, 3, 2, 1),
    ("round4_replay --forge", "round4_replay", {"forge_only": True}, 4, 1, 1),
    ("round4_replay (warped)", "round4_replay", {"runs": 3}, 4, 3, 2),
]
BROWSERLESS = {"round4_replay --forge"}


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ATTACKS, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def server_level():
    with urllib.request.urlopen(f"{BASE_URL}/behavior/sessions?n=1", timeout=5) as r:
        return json.loads(r.read())["level"]


def recent_bot_bytes():
    with urllib.request.urlopen(f"{BASE_URL}/behavior/sessions?n=60", timeout=5) as r:
        decisions = json.loads(r.read())["decisions"]
    return [d["bytes"] for d in decisions if d["label"].startswith("round")]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--round", type=int, required=True, choices=range(0, 5))
    ap.add_argument("--skip-browser", action="store_true", help="skip the Playwright attacks")
    args = ap.parse_args()

    try:
        level = server_level()
    except OSError:
        print(f"❌ Demo site not reachable on {BASE_URL}. Is it running?")
        return 1
    print(f"=== Checkpoint: Round {args.round} (server at DEFENSE_LEVEL={level}) ===\n")
    if level != args.round:
        print(f"❌ Expected DEFENSE_LEVEL={args.round}. Restart the demo site with:")
        print(f"     DEFENSE_LEVEL={args.round} python demo_site/app.py")
        return 1

    failures = 0
    print("Bot traffic                         reserved  challenged  blocked   expected")
    for label, module, kwargs, first, runs, must in ATTACKS_PLAN:
        if args.skip_browser and label not in BROWSERLESS:
            print(f"  ⏭️  {label:<31} skipped (--skip-browser)")
            continue
        results = load(module).run(**kwargs)
        n_res = sum(r["status"] == "reserved" for r in results)
        n_ch = sum(r["status"] == "challenge" for r in results)
        n_bl = sum(r["status"] == "blocked" for r in results)
        if level >= first:
            ok = n_ch + n_bl >= must
            expectation = f"stopped ≥ {must}/{runs}"
        else:
            ok = n_res >= 1
            expectation = "gets through"
        failures += not ok
        print(f"  {'✅' if ok else '❌'} {label:<31} {n_res:>4}      {n_ch:>4}      {n_bl:>4}     {expectation}")

    print("\nReal users: 40 synthetic humans")
    people = humans.run()
    blocked = [r for r in people if r["status"] == "blocked"]
    challenged = [r for r in people if r["status"] == "challenge"]
    failures += bool(blocked)
    print(f"  {'✅' if not blocked else '❌'} blocked {len(blocked)}/{len(people)}   "
          f"challenged {len(challenged)}/{len(people)}")
    for r in blocked + challenged:
        print(f"       {'❌' if r['status'] == 'blocked' else '🟡'} {r['profile']}: {'; '.join(r['reasons'])}")

    mine = []
    for path in sorted(glob.glob(os.path.join(HERE, "traces", "*.json"))):
        trace = json.load(open(path))
        if trace.get("source") == "browser":
            mine.append((os.path.basename(path), *score_offline(trace, level)))
    print("\nReal users: your recorded traces (offline, Levels 1-3)")
    if not mine:
        print("  ⚠️  none yet: reserve a pair in your browser, then `python tools/save_trace.py --name <you>`")
    for name, score, reasons, verdict in mine:
        mark = {"allow": "✅", "challenge": "🟡", "block": "❌"}[verdict]
        failures += verdict == "block"
        print(f"  {mark} {name:<24} {verdict:<9} score={score}  {'; '.join(reasons)}")

    timings = [r["score_ms"] for r in people if r["score_ms"] is not None]
    sizes = [r["bytes"] for r in people if r["profile"] in ("mouse", "trackpad", "tremor")]
    bot_sizes = recent_bot_bytes()
    print("\nDefender cost")
    if timings:
        p95 = statistics.quantiles(timings, n=20)[-1]
        print(f"  scoring:   median {statistics.median(timings):.2f} ms, p95 {p95:.2f} ms per reservation")
    if sizes:
        print(f"  telemetry: median {statistics.median(sizes) / 1024:.1f} KB per mouse user, "
              f"max {max(sizes) / 1024:.1f} KB (1000 Hz mice)")
    if bot_sizes:
        print(f"             median {statistics.median(bot_sizes) / 1024:.1f} KB per Playwright bot (60 Hz, no coalescing)")

    print()
    if failures:
        print(f"❌ {failures} check(s) differ from the expected results. Compare with the expected-results table in README.md.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
