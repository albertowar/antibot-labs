"""
W3 Ch1 — Round checkpoint

Run at the end of every round to see where you stand, measuring BOTH sides:

    bots:    this round's attack — how many pairs it buys
    humans:  the 12 simulated customers (tools/legit_traffic.py) — allowed,
             challenged or blocked
    cost:    defender scoring time (Server-Timing) per action

A round passes when the attack is handled as that round expects AND no
legitimate customer is BLOCKED. Challenged customers are reported as friction,
not failure — Round 4's whole lesson is that the signal which stops the farm
also adds friction for rooted / custom-ROM / old devices.

Round 1 is the exception: the attack is SUPPOSED to get through at L0 (that is
the vulnerability), and the round's defense — certificate pinning — is checked
separately (does a pinned client refuse an intercepted certificate?).

Fell behind, or want to see the finished defense? Each round's TODO lives in one
module. `--catch-up` copies this round's reference solution over your edits
(saving a .bak first).

Run (store running at the round's level):
    python tools/checkpoint.py --round 2
    python tools/checkpoint.py --round 3 --catch-up
"""

import argparse
import importlib
import os
import shutil
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attacks"))
import legit_traffic  # noqa: E402
from lab import BASE_URL, admin, ensure_local, server_status  # noqa: E402

LAB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

ROUNDS = {
    1: {"attack": "round1_intercept", "kwargs": {"sessions": 6}, "level": 0, "expect": "through"},
    2: {"attack": "round2_unpin", "kwargs": {"sessions": 6}, "level": 1, "expect": "blocked"},
    3: {"attack": "round3_replay", "kwargs": {"sessions": 6}, "level": 2, "expect": "blocked"},
    4: {"attack": "round4_farm", "kwargs": {"sessions": 12}, "level": 3, "expect": "blocked"},
}
SOLUTIONS = {1: "pinned_client.py", 2: "attestation.py", 3: "request_signing.py", 4: "device_verdict.py"}


def catch_up(rnd):
    name = SOLUTIONS[rnd]
    src = os.path.join(LAB_DIR, "solutions", f"round{rnd}", name)
    dst = os.path.join(LAB_DIR, "defenses", name)
    if not os.path.exists(src):
        sys.exit(f"No reference solution at {os.path.relpath(src, LAB_DIR)}")
    shutil.copy2(dst, dst + ".bak")
    shutil.copy2(src, dst)
    print(f"✅ Copied solutions/round{rnd}/{name} -> defenses/{name} (your version saved as {name}.bak)")
    print("   Restart the demo site for the change to take effect.\n")


def run_attack(spec):
    module = importlib.import_module(spec["attack"])
    importlib.reload(module)
    return module, module.run(**spec["kwargs"])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--round", type=int, required=True, choices=sorted(ROUNDS))
    parser.add_argument("--catch-up", action="store_true", help="apply this round's reference solution")
    parser.add_argument("--skip-bot", action="store_true", help="only measure the legitimate users")
    args = parser.parse_args()
    ensure_local()
    spec = ROUNDS[args.round]

    if args.catch_up:
        catch_up(args.round)

    try:
        status = server_status()
    except Exception:
        print(f"❌ Demo store not reachable on {BASE_URL}. Start it: python demo_site/app.py")
        return 1
    level = status["level"]
    print(f"=== Checkpoint: Round {args.round} (store at DEFENSE_LEVEL={level}) ===\n")
    if level != spec["level"]:
        print(f"❌ This round needs DEFENSE_LEVEL={spec['level']}. Restart the store:")
        print(f"     DEFENSE_LEVEL={spec['level']} REDIS_URL=memory:// python demo_site/app.py")
        return 1

    admin("POST", "/admin/reset")  # clear the drop + counters so counts start from zero
    failures = 0

    if not args.skip_bot:
        module, result = run_attack(spec)
        got = result["succeeded"]
        if spec["expect"] == "through":
            ok = got > 0
            verb = "got through (the Round 1 vulnerability)"
        else:
            ok = got == 0
            verb = f"stopped at level {spec['level']}"
        failures += not ok
        print("Bot traffic")
        print(f"  {'✅' if ok else '❌'} {spec['attack']:<20} {got}/{result['attempts']} pairs ({verb})")
        for reason in result["top_reasons"]:
            print(f"       - {reason}")
        print(f"  attacker cost: {result['wall_s_per_attempt']} s wall per attempt "
              f"({result['wall_s']} s total)")
        if args.round == 1:
            blocks = module.pin_demo()
            print(f"  {'✅' if blocks else '❌'} certificate pinning {'refuses' if blocks else 'does NOT refuse'} "
                  f"an intercepted certificate (defenses/pinned_client.py)")
            failures += not blocks
        print()

    print("Legitimate users (12 simulated customers)")
    legit = legit_traffic.run()
    blocked = [r for r in legit if r["outcome"] == "block"]
    challenged = [r for r in legit if r["outcome"] == "challenge"]
    errors = [r for r in legit if r["outcome"] not in ("allow", "block", "challenge")]
    allowed = len(legit) - len(blocked) - len(challenged) - len(errors)
    failures += bool(blocked) + bool(errors)
    print(f"  {'✅' if not (blocked or errors) else '❌'} {allowed}/{len(legit)} allowed, "
          f"{len(challenged)} challenged, {len(blocked)} blocked, {len(errors)} errored")
    for r in blocked + errors:
        print(f"       ❌ {r['persona']:<20} {r['stage']:<6} {r['reasons'][:2]}")
    if challenged:
        personas = sorted({r["persona"] for r in challenged})
        print(f"       ⚠️  challenged (friction): {', '.join(personas)}")

    timings = [r["score_ms"] for r in legit if r["score_ms"] is not None]
    if timings:
        p95 = statistics.quantiles(timings, n=20)[-1] if len(timings) >= 2 else timings[0]
        print(f"\nDefender cost: scoring median {statistics.median(timings):.2f} ms, p95 {p95:.2f} ms per buy")

    print()
    if failures:
        print(f"❌ Round {args.round}: {failures} check(s) differ from what this round expects.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
