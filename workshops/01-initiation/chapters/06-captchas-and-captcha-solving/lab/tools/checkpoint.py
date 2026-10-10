"""
Chapter 6 — Round Checkpoint (Section 6.6)

Run at the end of every round to check that you are where you should be,
and to measure BOTH sides of the defense:

  - bot traffic:   every attack introduced so far vs. the expected result
  - real users:    40 simulated shoppers (tools/legit_traffic.py): completed,
                   challenged, lost, and why
  - defender cost: siteverify, CAPTCHA generation and check time (Server-Timing)

Fell behind? --catch-up copies the reference solutions for rounds 1..N into
defenses/ (your versions are backed up to defenses/_backup/), waits for the
demo site to reload, then runs the checkpoint.

Run:
    python tools/checkpoint.py 2
    python tools/checkpoint.py 2 --catch-up
"""

import argparse
import hashlib
import importlib.util
import os
import shutil
import statistics
import sys
import time
from pathlib import Path

import httpx

LAB = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(LAB / "attacks"))
sys.path.insert(0, str(LAB / "defenses"))
import legit_traffic  # noqa: E402
from labkit import BASE_URL, PROVIDER_URL, redis_client, require_local  # noqa: E402

# attack -> (round introduced, {round: (max success rate, label)})
EXPECTED = {
    "round0_mass_register": (0, {0: (None, "gets through"), 1: (0.0, "blocked")}),
    "round1_bypass": (1, {1: (0.0, "blocked")}),
    "round2_cookie_replay": (2, {2: (0.0, "blocked")}),
    "round3_ocr": (3, {3: (0.25, "≤25% succeed"), 4: (0.10, "≤10% succeed")}),
    "round4_retry_ocr": (4, {4: (0.10, "≤10% of goal")}),
    "round4_solver_farm": (4, {4: (0.20, "≤20% of goal")}),
}
MIN_SUCCESS_WHEN_OPEN = 0.9
HUMAN_BUDGET = {4: {"max_lost": 3, "max_challenged": 8}}


def load(name):
    spec = importlib.util.spec_from_file_location(name, LAB / "attacks" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def disk_hashes():
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()[:12]
            for p in sorted((LAB / "defenses").glob("*.py"))}


def status():
    return httpx.get(f"{BASE_URL}/lab/status", timeout=5).json()


def catch_up(round_no):
    backup = LAB / "defenses" / "_backup" / time.strftime("%Y%m%d-%H%M%S")
    for k in range(1, round_no + 1):
        for src in sorted((LAB / "solutions" / f"round{k}").glob("*.py")):
            dst = LAB / "defenses" / src.name
            if dst.exists() and dst.read_bytes() != src.read_bytes():
                backup.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dst, backup / src.name)
            shutil.copyfile(src, dst)        # fresh mtime, so the reloader notices
            print(f"  installed solutions/round{k}/{src.name}")
    if backup.exists():
        print(f"  your previous versions are in {backup.relative_to(LAB)}")
    want = disk_hashes()
    for _ in range(40):                      # the Flask reloader takes a second or two
        time.sleep(0.5)
        try:
            if status()["modules"] == want:
                print("  demo site reloaded with the reference defenses\n")
                return True
        except httpx.HTTPError:
            pass
    print("❌ The demo site did not reload. Restart it, then run the checkpoint again.")
    return False


def percentile(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))] if values else 0.0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("round", type=int, choices=range(0, 5))
    parser.add_argument("--catch-up", action="store_true",
                        help="install the reference solutions for rounds 1..N first")
    args = parser.parse_args()
    require_local()

    try:
        st = status()
    except httpx.HTTPError:
        print(f"❌ Demo site not reachable on {BASE_URL}. Is it running?")
        return 1
    if st["level"] != args.round:
        print(f"❌ The demo site runs DEFENSE_LEVEL={st['level']}; Round {args.round} needs "
              f"{args.round}. Restart it with:\n     DEFENSE_LEVEL={args.round} python demo_site/app.py")
        return 1
    if args.round >= 1:
        try:
            httpx.post(f"{PROVIDER_URL}/lab/reset", timeout=5)
        except httpx.HTTPError:
            print(f"❌ Mock provider not reachable on {PROVIDER_URL}. "
                  f"Start it with: python provider/mock_turnstile.py")
            return 1
    if args.catch_up and not catch_up(args.round):
        return 1

    print(f"=== Checkpoint: Round {args.round} "
          f"(DEFENSE_LEVEL={st['level']}, generator={st['style']}) ===\n")
    failures = 0
    r = redis_client()

    print("Bot traffic")
    solver = None
    for name, (introduced, expectations) in EXPECTED.items():
        if introduced > args.round:
            continue
        r.flushdb()
        module = load(name)
        if name in ("round3_ocr", "round4_retry_ocr"):
            from ocr_solver import Solver
            solver = solver or Solver(st["style"]).train()
            s = module.run(solver=solver)
        elif name == "round4_solver_farm":
            s = module.run(seed=4)
        else:
            s = module.run()
        rate = s["successes"] / max(1, s.get("goal", s["attempts"]))
        limit, label = expectations[max(k for k in expectations if k <= args.round)]
        ok = rate >= MIN_SUCCESS_WHEN_OPEN if limit is None else rate <= limit
        failures += not ok
        extra = f" · ${s['spent']:.3f} on solving" if "spent" in s else ""
        print(f"  {'✅' if ok else '❌'} {name:<22} {s['successes']:>2}/"
              f"{s.get('goal', s['attempts']):<3} succeeded  (expected: {label}){extra}")
        if not ok and s.get("reasons"):
            print(f"       server said: {s['reasons']}")

    print("\nReal users (40 simulated shoppers)")
    r.flushdb()
    if args.round >= 1:
        httpx.post(f"{PROVIDER_URL}/lab/reset", timeout=5)
    results = legit_traffic.run()
    h = legit_traffic.summarize(results)
    print(f"  completed {h['completed']}/{h['users']} · challenged {h['challenged']}/{h['users']} "
          f"· {h['challenges']} CAPTCHAs shown · median journey {h['median_s']:.0f} s")
    reg_fp = [x for x in h["lost"] if x["lost"].startswith("register")]
    if reg_fp:
        failures += 1
        print(f"  ❌ {len(reg_fp)} real users could not register: {reg_fp[0]['lost']}")
    for x in h["lost"]:
        if x not in reg_fp:
            print(f"  ⚠️  user {x['user']:>2} lost: {x['lost']}")
    budget = HUMAN_BUDGET.get(args.round)
    if budget:
        over = len(h["lost"]) > budget["max_lost"] or h["challenged"] > budget["max_challenged"]
        failures += over
        print(f"  {'❌' if over else '✅'} budget: ≤{budget['max_lost']} lost, "
              f"≤{budget['max_challenged']} challenged")

    timings = {}
    for res in results:
        for t in res["timings"]:
            for k, v in t.items():
                timings.setdefault(k, []).append(v)
    if timings:
        print("\nDefender cost (per request)")
        for k, v in sorted(timings.items()):
            print(f"  {k:<14} median {statistics.median(v):6.2f} ms · p95 {percentile(v, 0.95):6.2f} ms")

    print()
    if failures:
        print(f"❌ {failures} check(s) differ from the expected results. "
              f"Fix the TODOs, or run with --catch-up.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
