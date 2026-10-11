"""
W4 Ch4 — Round checkpoint: measure both sides

Run at the end of each round, with the store at that round's DEFENSE_LEVEL. It:

    1. resets the drop and decisions
    2. runs the round's attack (a browser agent, so this needs Chromium; set
       HEADLESS=1 with no display) and reports orders placed / challenged / refused
    3. runs the 40 simulated customers and reports what happened to the humans
       (blocking any is a failure) and to the legit-agent cohort
    4. reads /admin/decisions for the scoreboard and the W2 shadow score

A round passes when the round's bot meets its expectation (see ROUNDS) AND no
HUMAN customer is blocked. Challenges are friction, not failure.

Fell behind, or want the finished defence? --catch-up installs the reference
solutions for rounds 1..N over your files (saving a .bak). Restart the store afterwards.

Run (from lab/):
    DEMO_URL=http://127.0.0.1:8404 python tools/checkpoint.py --round 2
    python tools/checkpoint.py --round 3 --catch-up
"""

import argparse
import importlib
import os
import shutil
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
import legit_traffic  # noqa: E402
from lab import BASE_URL, admin, decisions, ensure_local, server_status  # noqa: E402

# round -> attack module, kwargs, the bot metric, and what level N must achieve.
#   expect: "stopped" (0 orders placed) or "through" (>0, the attack that motivates the next round)
ROUNDS = {
    1: {"attack": "round1_undeclared_agent", "kwargs": {"sessions": 5}, "expect": "through",
        "note": "L1 policy only sorts honest agents; the undeclared agent still buys. Round 2 closes this."},
    2: {"attack": "round2_humanized_agent", "kwargs": {"sessions": 5}, "expect": "through",
        "note": "humanized agent clears the behaviour score; it buys. Round 4's gate is what finally caps it."},
    3: {"attack": "round3_forged_agent", "kwargs": {"per_variant": 2}, "expect": "stopped",
        "note": "every forged identity is refused; the honest verified agent (round3_verified_agent) buys."},
    4: {"attack": "round4_fleet", "kwargs": {"sessions": 12}, "expect": "capped",
        "note": "the fleet is capped to the per-device limit (<=2) despite passing the step-up."},
}
SOLUTIONS = {1: "agent_policy.py", 2: "agent_behavior.py", 3: "agent_identity.py", 4: "checkout_gate.py"}
CAP = 2  # 'capped' rounds: this many drop units or fewer is a pass


sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
import labnet  # noqa: E402


def catch_up(rnd):
    """Install the reference solutions for rounds 1..rnd (each of your files is kept once as .bak)."""
    installed = labnet.catch_up(LAB_DIR, rnd)
    for f in installed:
        print(f"  installed solutions -> {f}   (your version kept as {f}.bak; --restore puts it back)")
    if not installed:
        print("  nothing to install up to this round")
    print("   Restart the demo site for the change to take effect.\n")


def run_attack(spec, base):
    module = importlib.import_module(spec["attack"])
    importlib.reload(module)
    return module.run(base=base, **spec["kwargs"])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--round", type=int, required="--restore" not in sys.argv, choices=sorted(ROUNDS))
    parser.add_argument("--catch-up", action="store_true", help="install the reference solutions up to this round")
    parser.add_argument("--restore", action="store_true", help="put your .bak files back, then exit")
    parser.add_argument("--skip-bot", action="store_true", help="only measure the legitimate users")
    args = parser.parse_args()
    if args.restore:
        restored = labnet.restore(LAB_DIR)
        print("restored: " + (", ".join(restored) or "nothing to restore (no .bak files)"))
        return 0
    ensure_local()
    if args.catch_up:
        catch_up(args.round)

    try:
        status = server_status()
    except Exception:
        print(f"❌ Demo store not reachable on {BASE_URL}. Start it: DEFENSE_LEVEL={args.round} python demo_site/app.py")
        return 1
    level = status["level"]
    print(f"=== Checkpoint: Round {args.round} (store at DEFENSE_LEVEL={level}) ===\n")
    if level != args.round:
        print(f"❌ This round needs DEFENSE_LEVEL={args.round}. Restart the store:")
        print(f"     DEFENSE_LEVEL={args.round} PORT={BASE_URL.rsplit(':', 1)[-1]} python demo_site/app.py")
        return 1

    spec = ROUNDS[args.round]
    admin("POST", "/admin/reset", params={"decisions": 1, "fresh_accounts": 1})
    since = server_status()["last_decision_id"]
    failures = 0

    if not args.skip_bot:
        result = run_attack(spec, BASE_URL)
        placed = result["succeeded"]
        if spec["expect"] == "stopped":
            ok = placed == 0
        elif spec["expect"] == "capped":
            ok = placed <= CAP
        else:
            ok = placed > 0
        failures += not ok
        print("Bot traffic")
        print(f"  {'✅' if ok else '❌'} {spec['attack']:<24} {placed}/{result['attempts']} orders placed  "
              f"(outcomes {result['outcomes']})")
        for reason in result["top_reasons"]:
            print(f"       - {reason[:110]}")
        print(f"  {spec['note']}")
        print(f"  attacker cost: {result['wall_s']} s wall ({result['wall_s_per_attempt']} s/session), "
              f"{result['steps_total']} agent steps\n")

    print("Legitimate users (40 simulated customers)")
    legit = legit_traffic.run(BASE_URL)
    humans = [r for r in legit if r["cohort"] == "human"]
    agents = [r for r in legit if r["cohort"] == "legit-agent"]
    h_block = [r for r in humans if r["outcome"] == "block"]
    h_chal = [r for r in humans if r["outcome"] == "challenge"]
    h_err = [r for r in humans if r["outcome"] not in ("allow", "challenge", "block")]
    failures += bool(h_block) + bool(h_err)
    print(f"  {'✅' if not h_block and not h_err else '❌'} humans: "
          f"{len(humans) - len(h_block) - len(h_chal) - len(h_err)}/{len(humans)} allowed, "
          f"{len(h_chal)} challenged, {len(h_block)} blocked, {len(h_err)} errored")
    for r in h_block + h_err:
        print(f"       ❌ {r['persona']:<14} {r['stage']:<7} {r['reasons'][:2]}")
    if h_chal:
        print(f"       ⚠️  challenged (friction): {', '.join(sorted({r['persona'] for r in h_chal}))}")
    a_allow = sum(r["outcome"] == "allow" for r in agents)
    print(f"  legit agents: {a_allow}/{len(agents)} bought "
          f"({'served once the store supports verified+mandated agents' if level < 3 and a_allow == 0 else 'ok'})")

    rows = [d for d in decisions(since_id=since) if d["action"] == "checkout"]
    timings = [d["score_ms"] for d in rows if d.get("score_ms") is not None]
    if timings:
        p95 = statistics.quantiles(timings, n=20)[-1] if len(timings) >= 2 else timings[0]
        print(f"\nDefender cost: checkout scoring median {statistics.median(timings):.1f} ms, p95 {p95:.1f} ms")

    print()
    if failures:
        print(f"❌ Round {args.round}: {failures} check(s) differ from what this round expects.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
