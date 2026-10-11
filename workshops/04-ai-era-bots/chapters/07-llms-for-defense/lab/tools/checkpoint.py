"""
W4 Chapter 7 — Round checkpoint (catch-up, restore, scoreboard)

    python tools/checkpoint.py --round N              # triage the round's run, then score it
    python tools/checkpoint.py --round N --catch-up   # install the reference solutions for rounds 1..N first
    python tools/checkpoint.py --restore              # put your .bak files back and exit

Rounds and what they change (each round's reference lives in solutions/roundN/):

    0  baseline bots, heuristic + LLM triage               (no student code)
    1  injected User-Agent / Referer beat the naive prompt  (no student code: watch it fail)
    2  defenses/sanitize.py + defenses/triage.py            input caps, phrase redaction, fenced prompt,
                                                            output validation
    3  defenses/gate.py + defenses/cluster.py               pre-filter, cluster, replay candidate rules
                                                            against verified customers

Run the round's attack first. For rounds 0-2 this script triages that run with the
round's prompt (naive, then --hardened) and scores the verdicts against ground truth;
for round 3 it prints the operations steps and the live view. PASS/FAIL thresholds and an expected-results table are
still to be written (see the chapter entry in the root TODO.md).
"""

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, LAB_DIR)  # lab root: labnet.py
import labnet  # noqa: E402

# round -> (attack command, the run it tags, triage flags). Triage writes verdicts under
# (run, tag); the scoreboard reads the same pair.
ROUNDS = {
    0: ("python tools/simulate.py   (600 real users + baseline bots)", "simulate-1", []),
    1: ("python attacks/round1_injected_ua.py --n 40 --variant both", "round1_injected_ua", []),
    2: ("python attacks/round2_stitched.py --mode stitch   (then --mode bait)", "round2_stitched", ["--hardened"]),
    3: ("python attacks/round3_token_flood.py --n 400", "round3_token_flood", None),
}
ROUND3_STEPS = """  Round 3 is an operations loop, not one command:
    defenses/triage.py -> defenses/rulesmith.py (candidate rules) -> defenses/gate.py (replay
    against verified customers) -> tools/approve.py (a person approves) -> DEFENSE_LEVEL=2 (enforce).
  See each tool's --help. This checkpoint prints the live view: real users and bots blocked at the edge."""


def catch_up(rnd):
    """Install the reference solutions for rounds 1..rnd (each of your files is kept once as .bak)."""
    installed = labnet.catch_up(LAB_DIR, rnd)
    for f in installed:
        print(f"  installed solutions -> {f}   (your version kept as {f}.bak; --restore puts it back)")
    if not installed:
        print("  nothing to install up to this round")
    print("  Restart the demo site, re-run tools/simulate.py and the round's attack, then this checkpoint.\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--round", type=int, choices=range(0, 4))
    ap.add_argument("--catch-up", action="store_true", help="install the reference solutions up to this round")
    ap.add_argument("--restore", action="store_true", help="put your .bak files back, then exit")
    args = ap.parse_args()
    if args.restore:
        restored = labnet.restore(LAB_DIR)
        print("restored: " + (", ".join(restored) or "nothing to restore (no .bak files)"))
        return 0
    if args.round is None:
        ap.error("--round is required (unless --restore)")
    labnet.require_local()
    if args.catch_up:
        catch_up(args.round)
    attack, run, flags = ROUNDS[args.round]
    print(f"=== Round {args.round}: attack = {attack} ===")
    py = sys.executable
    if flags is None:
        print(ROUND3_STEPS)
        return subprocess.call([py, os.path.join(HERE, "scoreboard.py"), "--live"], cwd=LAB_DIR)
    tag = "checkpoint" + ("-hardened" if flags else "")
    rc = subprocess.call([py, os.path.join(LAB_DIR, "defenses", "triage.py"), "--since-run", run, "--tag", tag, *flags],
                         cwd=LAB_DIR)
    if rc:
        return rc
    return subprocess.call([py, os.path.join(HERE, "scoreboard.py"), "--triage", "--run", run, "--tag", tag], cwd=LAB_DIR)

if __name__ == "__main__":
    sys.exit(main())
