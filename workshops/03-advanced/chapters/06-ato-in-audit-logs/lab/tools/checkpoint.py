"""
Chapter 6: round checkpoints and catch-up.

    python tools/checkpoint.py --round N            # run the reference detector for round N (1-5) and score it
    python tools/checkpoint.py --round N --catch-up # also copy its suspects to lab/suspects_rN.csv so the next notebook starts from it
    python tools/checkpoint.py --all                # rounds 1..5 in order (what the README's expected-results table comes from)
    python tools/checkpoint.py --reveal             # score your own lab/suspects_r5.csv with names shown

Reference detectors live in solutions/round{1,2,3,4,5}_*.py and read the previous
round's checkpoint, so run them in order (or use --all). Rounds 4 and 5 are judged
on what they add to the previous round's file (score.py --prev).
"""

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
SOL = os.path.join(LAB, "solutions")
CK = os.path.join(SOL, "checkpoints")
SCRIPTS = {1: "round1_rules.py", 2: "round2_graph.py", 3: "round3_anomaly.py", 4: "round4_invariant.py", 5: "round5_session_queue.py"}


def run_round(n, catch_up=False):
    os.makedirs(CK, exist_ok=True)
    print(f"\n######## Round {n}: {SCRIPTS[n]} ########")
    subprocess.run([sys.executable, os.path.join(SOL, SCRIPTS[n])], check=True)
    if catch_up:
        src = os.path.join(CK, f"suspects_r{n}.csv")
        dst = os.path.join(LAB, f"suspects_r{n}.csv")
        shutil.copy(src, dst)
        print(f"catch-up: copied {os.path.relpath(src, LAB)} -> {os.path.relpath(dst, LAB)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--round", type=int, choices=[1, 2, 3, 4, 5])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--catch-up", action="store_true")
    ap.add_argument("--reveal", nargs="?", const=os.path.join(LAB, "suspects_r5.csv"), help="score a suspects file with campaign names shown")
    args = ap.parse_args()
    if args.reveal:
        subprocess.run([sys.executable, os.path.join(HERE, "score.py"), args.reveal, "--reveal"], check=False)
        return
    if args.all:
        for n in (1, 2, 3, 4, 5):
            run_round(n, args.catch_up)
    elif args.round:
        run_round(args.round, args.catch_up)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
