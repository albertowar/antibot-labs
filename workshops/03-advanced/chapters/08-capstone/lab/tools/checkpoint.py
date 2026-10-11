"""
Capstone — Round checkpoint (Section 8.7)

Run at the end of every round to see where you stand, measuring BOTH sides:

    bots:   this round's attack — how many of its moves got through
    humans: the 40 simulated browser customers (tools/legit_traffic.py) AND the
            legit API clients (tools/api_traffic.py) — allowed, challenged or blocked
    cost:   defender scoring time (Server-Timing) and attacker time per attempt

A round passes when the attack is stopped at the round's level AND no legitimate
customer or API client is blocked. Challenges count as friction, reported but
not failed.

Each W3 round edits one defense module; --catch-up copies that round's reference
solution over your edits (saving a .bak), and re-running without it restores
your work.

    DEFENSE_LEVEL per round:  0->L4 (inherited stack), 1->L5, 2->L6, 3->L7, 4->L7
Run (store at the round's level):
    python tools/checkpoint.py --round 1
    python tools/checkpoint.py --round 2 --catch-up
"""

import argparse
import importlib
import os
import shutil
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attacks"))
import api_traffic  # noqa: E402
import legit_traffic  # noqa: E402
from lab import BASE_URL, admin, ensure_local, server_status  # noqa: E402

LAB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# round -> attack module, the DEFENSE_LEVEL it runs at, the level that should stop
# it, and the label for its success count.
ROUNDS = {
    0: {"attack": "round0_naive", "level": 4, "blocks_at": 4, "label": "pairs bought"},
    1: {"attack": "round1_api", "level": 5, "blocks_at": 5, "label": "API techniques"},
    2: {"attack": "round2_streaming", "level": 6, "blocks_at": 6, "label": "patterns evaded"},
    3: {"attack": "round3_skimmer", "level": 7, "blocks_at": 7, "label": "exfiltrations"},
    4: {"attack": "round4_integrated", "level": 7, "blocks_at": 7, "label": "pairs bought"},
}
# Which defense file each round edits (filename, directory under lab/), and its
# reference solution in solutions/roundN/.
SOLUTIONS = {
    1: ("api_hardening.py", "defenses"),
    2: ("detectors.py", "defenses/streaming"),
    3: ("supply_chain.py", "defenses"),
}


def catch_up(rnd):
    entry = SOLUTIONS.get(rnd)
    if not entry:
        print(f"  (round {rnd} has no student TODO)")
        return
    name, subdir = entry
    src = os.path.join(LAB_DIR, "solutions", f"round{rnd}", name)
    dst = os.path.join(LAB_DIR, subdir, name)
    if not os.path.exists(src):
        sys.exit(f"No reference solution at {os.path.relpath(src, LAB_DIR)}")
    shutil.copy2(dst, dst + ".bak")
    shutil.copy2(src, dst)
    print(f"✅ Copied solutions/round{rnd}/{name} -> {subdir}/{name} (your version saved as {name}.bak)")
    print("   Restart the demo site for the change to take effect.\n")


def run_attack(spec):
    module = importlib.import_module(spec["attack"])
    importlib.reload(module)
    return module.run()


def measure_humans():
    """Browser customers + API clients, with a normalized result shape."""
    rows = legit_traffic.run()
    for r in rows:
        r.setdefault("kind", "browser")
    api = api_traffic.run()
    for r in api:
        r["kind"] = "api"
    return rows + api


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--round", type=int, required=True, choices=sorted(ROUNDS))
    parser.add_argument("--catch-up", action="store_true", help="apply this round's reference solution")
    parser.add_argument("--skip-bot", action="store_true", help="only measure the legitimate traffic")
    args = parser.parse_args()
    ensure_local()
    spec = ROUNDS[args.round]

    if args.catch_up:
        catch_up(args.round)

    try:
        status = server_status()
    except Exception:
        print(f"❌ Demo store not reachable on {BASE_URL}. Start it and the services.")
        return 1
    level = status["level"]
    print(f"=== Checkpoint: Round {args.round} (store at DEFENSE_LEVEL={level}) ===\n")
    if level != spec["level"]:
        print(f"❌ This round needs DEFENSE_LEVEL={spec['level']}. Restart the store:")
        print(f"     DEFENSE_LEVEL={spec['level']} python demo_site/app.py")
        return 1
    if not status.get("model_loaded"):
        print("⚠️  L3 session model not loaded (python tools/train_model.py). The inherited L3 layer\n"
              "    scores 0 until you train it; the W3 layers in this round are unaffected.\n")

    admin("POST", "/admin/reset")  # clear the drop so counts start from zero
    failures = 0

    if not args.skip_bot:
        result = run_attack(spec)
        got = result["succeeded"]
        should_stop = level >= spec["blocks_at"]
        ok = (got == 0) if should_stop else (got > 0)
        failures += not ok
        verb = "stopped" if should_stop else "expected to get through"
        print("Bot traffic")
        print(f"  {'✅' if ok else '❌'} {spec['attack']:<22} {got} {spec['label']} "
              f"({verb} at level {spec['blocks_at']})")
        for reason in result["top_reasons"]:
            print(f"       - {reason}")
        if result.get("browser_proof"):
            print(f"       browser proof: {result['browser_proof']}")
        print(f"  attacker cost: {result['wall_s_per_attempt']} s wall per attempt "
              f"({result['wall_s']} s total)\n")

    print("Legitimate traffic (40 browser customers + 3 API clients)")
    legit = measure_humans()
    blocked = [r for r in legit if r["outcome"] == "block"]
    challenged = [r for r in legit if r["outcome"] == "challenge"]
    errors = [r for r in legit if r["outcome"] not in ("allow", "block", "challenge")]
    failures += bool(blocked)
    allowed = len(legit) - len(blocked) - len(challenged) - len(errors)
    print(f"  {'✅' if not blocked else '❌'} {allowed}/{len(legit)} allowed, "
          f"{len(challenged)} challenged, {len(blocked)} blocked, {len(errors)} errored/other")
    for r in blocked:
        print(f"       ❌ {r['persona']:<16} {r['stage']:<10} {r['reasons'][:2]}")
    if challenged:
        names = sorted({r["persona"] for r in challenged})
        print(f"       ⚠️  challenged (friction): {', '.join(names)}")

    timings = [r["score_ms"] for r in legit if r.get("score_ms") is not None]
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
