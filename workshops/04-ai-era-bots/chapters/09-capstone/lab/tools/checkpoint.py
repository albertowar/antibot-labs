"""
W4 Ch9 Capstone — round checkpoint: measure both sides

Run at the end of each round, with the store at that round's DEFENSE_LEVEL. It
resets the drop and the log, runs the round's attack and the legitimate mix,
and prints whether the round's targets are met AND no legitimate user is
blocked. Challenges are friction, not failure.

Fell behind, or want the finished defence? --catch-up installs the reference
solutions for rounds 1..N over your files (saving a .bak) and, for Round 2, the
reference policy. Restart the store afterwards.

    DEMO_URL=http://127.0.0.1:8409 python tools/checkpoint.py --round 1
    python tools/checkpoint.py --round 2 --catch-up
    python tools/checkpoint.py --round 4 --record exercises/governance_record.md
"""

import argparse
import importlib
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "attacks"))
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
import legit_traffic  # noqa: E402
import personas  # noqa: E402
import scoreboard  # noqa: E402
from lab import BASE_URL, admin, ensure_local, server_status  # noqa: E402

SOLUTIONS = {1: ["crawl_governance.py"], 2: ["agent_governance.py"], 3: ["deception_limits.py", "llm_guard.py"],
             4: ["oracle_guard.py"]}
ATTACK = {0: "round0_naive", 1: "round1_crawler_fleet", 2: "round2_agent_farm",
          3: ("round3_llm_extract", "round3_injector"), 4: "round4_integrated"}


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


def _targets(rnd, attack_result):
    """Per-round pass criteria on the attack side. Returns (ok, [lines])."""
    lines, ok = [], True
    if rnd == 1:
        r = attack_result
        checks = [("training crawler free pages", r["training"]["products"], 0),
                  ("impostor pages", r["impostor"]["products"], 0),
                  ("stealth second-pass pages", r["stealth_pass2"]["products"], 0),
                  ("paying crawler charged pages", -r["paying"]["charged_pages"], -1),
                  ("free-path leaks", r["free_path_leaks"], 0)]
        for name, got, ceil in checks:
            good = got <= ceil
            ok &= good
            lines.append(f"   {'✅' if good else '❌'} {name}: {abs(got)} (want {'0' if ceil == 0 else '>=1'})")
    elif rnd in (2, 4):
        farm = attack_result["farm"] if rnd == 4 else attack_result
        placed = farm["succeeded"]
        good = placed <= 2
        ok &= good
        lines.append(f"   {'✅' if good else '❌'} drop orders by the farm: {placed} (ceiling 2)")
        if rnd == 4:
            pr = attack_result["probe"]
            good = not pr["threshold_recoverable"]
            ok &= good
            lines.append(f"   {'✅' if good else '❌'} score oracle: threshold {'hidden' if good else 'RECOVERABLE'}")
            nv = attack_result["new_vendor"]["succeeded"]
            lines.append(f"   ℹ  new vendor orders before onboarding: {nv} (expected 0; onboard then re-run)")
    elif rnd == 3:
        ex, inj = attack_result
        good = ex["honeypot_hits"] >= 1 and ex["canaries"] >= 1
        ok &= good
        lines.append(f"   {'✅' if good else '❌'} extractor poisoned: honeypots {ex['honeypot_hits']}, canaries {ex['canaries']}")
        good = inj["hits"] == 0
        ok &= good
        lines.append(f"   {'✅' if good else '❌'} injections landed: {inj['hits']}/{inj['total']} (want 0)")
    return ok, lines


def run_attack(rnd, base):
    spec = ATTACK[rnd]
    if isinstance(spec, tuple):
        ex = importlib.import_module(spec[0]).run(base)
        inj = importlib.import_module(spec[1]).run(base)
        return (ex, inj)
    return importlib.import_module(spec).run(base)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--round", type=int, required="--restore" not in sys.argv, choices=[0, 1, 2, 3, 4])
    ap.add_argument("--catch-up", action="store_true")
    ap.add_argument("--restore", action="store_true", help="put your .bak files back, then exit")
    ap.add_argument("--record", help="Round 4: score a governance record against the 12-item checklist")
    args = ap.parse_args()
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
        print(f"❌ Store not reachable on {BASE_URL}. Start it: DEFENSE_LEVEL={args.round} PORT=8409 python demo_site/app.py")
        return 1
    if status["level"] != args.round:
        print(f"❌ This round needs DEFENSE_LEVEL={args.round}; the store is at {status['level']}. Restart it.")
        return 1
    print(f"=== Checkpoint: Round {args.round} (store at DEFENSE_LEVEL={status['level']}) ===\n")
    admin("POST", "/admin/reset", params={"decisions": 1, "fresh_accounts": 1})

    failures = 0
    print("Attack:")
    result = run_attack(args.round, BASE_URL)
    ok, lines = _targets(args.round, result)
    for line in lines:
        print(line)
    failures += not ok

    print("\nLegitimate traffic:")
    legit = legit_traffic.run(BASE_URL)
    blocked = [r for r in legit if r["outcome"] in ("block", "maze", "error")]
    by = legit_traffic.summarize(legit)
    for cohort in personas.COHORTS + personas.CRAWLER_COHORTS:
        row = by.get(cohort)
        if row:
            hurt = row["block"] + row["maze"]
            print(f"   {'✅' if hurt == 0 else '❌'} {cohort:<16} allow {row['allow']} challenge {row['challenge']} "
                  f"block {row['block']} maze {row['maze']}")
    failures += bool(blocked)

    if args.round == 4:
        import audit
        print()
        passed = audit.run(BASE_URL, args.record)
        failures += (passed != len(audit.CARDS))

    print("\n" + ("—" * 50))
    scoreboard.run(BASE_URL)
    print()
    if failures:
        print(f"❌ Round {args.round}: {failures} check group(s) differ from what this round expects.")
        return 1
    print(f"✅ Round {args.round} checkpoint passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
