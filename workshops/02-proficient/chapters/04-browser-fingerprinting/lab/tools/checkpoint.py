"""
Chapter 4 — Round Checkpoint (Section 4.7)

Run at the end of every round to check you are where you should be, and to
measure BOTH sides of the defense:

  - bot traffic:   every sign-up attack, accounts created vs. expected
  - real users:    the 40 simulated shoppers (tools/legit_traffic.py)
  - defender cost: collector time and payload size in a real Chromium,
                   server-side scoring and linking time (Server-Timing)

Each attack and the real-user run start from an empty store (POST
/lab/reset), so the numbers don't depend on what you ran before.

Fell behind? The defenses are already written; catching up means restarting
the demo site with the round's level:
    cd demo_site && DEFENSE_LEVEL=<round> python app.py

Run:
    python tools/checkpoint.py --round 3
    python tools/checkpoint.py --round 3 --signups 20   # slower, same verdicts
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
sys.path.insert(0, ATTACKS_DIR)

# attack script -> (first DEFENSE_LEVEL that stops it, accounts it still gets there)
EXPECTED = {
    "round1_headless_signup": (1, 0),
    "round2_patched_signup": (2, 0),
    "round3_replay_signup": (3, 3),
    "round4_noise_signup": (4, 3),
}


def load_attack(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ATTACKS_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def call(path, method="GET"):
    req = urllib.request.Request(f"{BASE_URL}{path}", method=method)
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def expected_created(name, level, signups):
    first_stopped_at, still_created = EXPECTED[name]
    return signups if level < first_stopped_at else min(signups, still_created)


def p95(values):
    return statistics.quantiles(values, n=20)[-1] if len(values) >= 2 else values[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--round", type=int, required=True, choices=range(0, 5))
    parser.add_argument("--signups", type=int, default=10, help="sign-ups per attack (default 10)")
    args = parser.parse_args()

    try:
        server = call("/fp-dashboard")
    except OSError:
        print(f"❌ Demo site not reachable on {BASE_URL}. Is it running?")
        return 1
    level, mode = server["level"], server["link_mode"]
    print(f"=== Checkpoint: Round {args.round} (server at DEFENSE_LEVEL={level}, LINK_MODE={mode}) ===\n")
    if level != args.round or mode != "rarity":
        print(f"❌ Expected DEFENSE_LEVEL={args.round} with rarity linking. Restart the demo site with:")
        print(f"     cd demo_site && DEFENSE_LEVEL={args.round} python app.py")
        return 1

    failures = 0
    collect_ms, payload_bytes = [], []

    print(f"Bot traffic ({args.signups} sign-ups per attack, fresh store each)")
    for name in EXPECTED:
        call("/lab/reset", "POST")
        results = load_attack(name).run(signups=args.signups)
        created = sum(r["status"] == 201 for r in results)
        want = expected_created(name, level, args.signups)
        ok = created == want
        failures += not ok
        collect_ms += [r["collect_ms"] for r in results]
        payload_bytes += [r["payload_bytes"] for r in results]
        print(f"  {'✅' if ok else '❌'} {name:<26} {created:>2}/{len(results)} accounts created "
              f"(expected {want})")
        if not ok:
            refused = [r for r in results if r["status"] != 201]
            for reason in (refused[0]["body"].get("reasons", []) if refused else [])[:3]:
                print(f"       {reason}")

    print("\nReal users (40 simulated shoppers, fresh store)")
    call("/lab/reset", "POST")
    legit = legit_traffic.run()
    blocked = [r for r in legit if r["status"] == 403]
    failures += bool(blocked)
    print(f"  {'✅' if not blocked else '❌'} {len(blocked)}/{len(legit)} refused")
    for cohort, (users, refused, suspicious) in legit_traffic.summarize(legit).items():
        if refused or suspicious:
            print(f"       {cohort:<18} {refused}/{users} refused, {suspicious} suspicious")
    for r in blocked:
        print(f"       {r['cohort']} user {r['user']}: {r['reasons'][:2]}")

    score_ms = [r["timing"]["fpscore"] for r in legit if "fpscore" in r["timing"]]
    link_ms = [r["timing"]["fplink"] for r in legit if "fplink" in r["timing"]]
    print("\nDefender cost")
    if collect_ms:
        print(f"  collector (headless Chromium): median {statistics.median(collect_ms):.0f} ms, "
              f"payload {statistics.median(payload_bytes) / 1024:.1f} KB")
    if score_ms:
        print(f"  server scoring:  median {statistics.median(score_ms):.2f} ms, p95 {p95(score_ms):.2f} ms")
        print(f"  linking queries: median {statistics.median(link_ms):.2f} ms, p95 {p95(link_ms):.2f} ms")

    print()
    if failures:
        print(f"❌ {failures} check(s) differ from the expected results. Ask your instructor.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
