"""
Chapter 9 — Round checkpoint (Section 9.7)

Run at the end of every round to see where you stand, measuring BOTH sides:

    bots:     this round's attack buys how many of the 50 pairs (or, in
              Round 4, confirms how many stolen credentials)
    humans:   the 40 simulated customers (tools/legit_traffic.py) — how many
              were allowed, challenged or blocked
    cost:     defender scoring time (Server-Timing) and attacker time per attempt

A round passes when the bot is stopped at the level that is supposed to stop
it AND no legitimate customer is blocked. Challenged customers are reported
as friction, not failure, except where a round's goal is zero challenges.

Fell behind, or want to see the finished defense? Each round's TODO lives in
one defense module. `--catch-up` copies this round's reference solution over
your edits (saving a .bak first); re-run without it to go back to your work.

Run (store running at the round's level):
    python tools/checkpoint.py --round 1
    python tools/checkpoint.py --round 4 --catch-up
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

# round -> (attack module, kwargs, how many pairs/creds a *success* is, result key,
#           first level that should stop it, human metric that must stay clean)
ROUNDS = {
    0: {"attack": "round0_naive", "kwargs": {}, "blocks_at": 0, "label": "pairs"},
    1: {"attack": "round1_patchright", "kwargs": {"sessions": 3}, "blocks_at": 1, "label": "pairs"},
    2: {"attack": "round2_camoufox", "kwargs": {"sessions": 3}, "blocks_at": 2, "label": "pairs"},
    3: {"attack": "round3_humanized_farm", "kwargs": {"sessions": 3}, "blocks_at": 3, "label": "pairs"},
    4: {"attack": "round4_stuffing", "kwargs": {"with_token": True, "limit": 60}, "blocks_at": 4,
        "label": "credentials confirmed", "success": "confirmed"},
}
# Which defense file each round edits, and its reference solution.
SOLUTIONS = {
    1: "fingerprint_coherence.py",
    2: "behavior_flow.py",
    3: "session_model.py",
    4: "login_risk.py",
}


def catch_up(rnd):
    name = SOLUTIONS.get(rnd)
    if not name:
        print(f"  (round {rnd} has no student TODO)")
        return
    src = os.path.join(LAB_DIR, "solutions", f"round{rnd}", name)
    dst = os.path.join(LAB_DIR, "defenses", name)
    if not os.path.exists(src):
        sys.exit(f"No reference solution at {os.path.relpath(src, LAB_DIR)}")
    shutil.copy2(dst, dst + ".bak")
    shutil.copy2(src, dst)
    print(f"✅ Copied solutions/round{rnd}/{name} -> defenses/{name} (your version saved as {name}.bak)")
    if rnd == 3:
        print("   Retrain the model so it uses the new threshold: python tools/train_model.py")
    print("   Restart the demo site for the change to take effect.\n")


def run_attack(spec):
    module = importlib.import_module(spec["attack"])
    importlib.reload(module)
    return module.run(**spec["kwargs"])


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
        print(f"❌ Demo store not reachable on {BASE_URL}. Start it (python demo_site/app.py) and the services.")
        return 1
    level = status["level"]
    print(f"=== Checkpoint: Round {args.round} (store at DEFENSE_LEVEL={level}) ===\n")
    if level != args.round:
        print(f"❌ This round needs DEFENSE_LEVEL={args.round}. Restart the store:")
        print(f"     DEFENSE_LEVEL={args.round} python demo_site/app.py")
        return 1
    if args.round >= 3 and not status.get("model_loaded"):
        print("❌ The L3 model isn't loaded. Run: python tools/train_model.py, then restart the store.")
        return 1

    admin("POST", "/admin/reset")  # clear the drop so counts start from zero
    failures = 0

    if not args.skip_bot:
        result = run_attack(spec)
        got = result.get(spec.get("success", "succeeded"), result["succeeded"])
        should_stop = level >= spec["blocks_at"]
        ok = (got == 0) if should_stop else (got > 0)
        failures += not ok
        verb = "stopped" if should_stop else "expected to get through"
        print("Bot traffic")
        print(f"  {'✅' if ok else '❌'} {spec['attack']:<22} {got} {spec['label']} "
              f"({verb} at level {spec['blocks_at']})")
        for reason in result["top_reasons"]:
            print(f"       - {reason}")
        print(f"  attacker cost: {result['wall_s_per_attempt']} s wall per attempt "
              f"({result['wall_s']} s total)\n")

    print("Legitimate users (40 simulated customers)")
    legit = legit_traffic.run()
    blocked = [r for r in legit if r["outcome"] == "block"]
    challenged = [r for r in legit if r["outcome"] == "challenge"]
    errors = [r for r in legit if r["outcome"] not in ("allow", "block", "challenge")]
    failures += bool(blocked) + bool(errors)
    print(f"  {'✅' if not blocked else '❌'} {len(legit) - len(blocked) - len(challenged) - len(errors)}"
          f"/{len(legit)} allowed, {len(challenged)} challenged, {len(blocked)} blocked, {len(errors)} errored")
    for r in blocked + errors:
        print(f"       ❌ {r['persona']:<16} {r['stage']:<8} {r['reasons'][:2]}")
    if challenged:
        personas = sorted({r["persona"] for r in challenged})
        print(f"       ⚠️  challenged (friction): {', '.join(personas)}")

    timings = [r["score_ms"] for r in legit if r["score_ms"] is not None]
    if timings:
        p95 = statistics.quantiles(timings, n=20)[-1] if len(timings) >= 2 else timings[0]
        print(f"\nDefender cost: scoring median {statistics.median(timings):.1f} ms, p95 {p95:.1f} ms per action")

    print()
    if failures:
        print(f"❌ Round {args.round}: {failures} check(s) differ from what this round expects.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
