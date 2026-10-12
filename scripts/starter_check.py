#!/usr/bin/env python3
"""
Are the starters in sync with the capstones they derive from, and do they still honour the contract?

    python scripts/starter_check.py            # drift + W3/W4 identity + boot every starter and run its smoke test
    python scripts/starter_check.py --no-boot  # drift and identity only (fast, no venv needed)

Each starter is booted with its own .venv if present (python3.12 -m venv .venv; pip install -r requirements.txt),
otherwise with the interpreter running this script.
"""

import argparse
import filecmp
import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CAPSTONES = {
    "workshops/01-initiation/chapters/08-mini-capstone/lab": ["workshops/02-proficient/starter"],
    "workshops/02-proficient/chapters/09-mini-capstone/lab": ["workshops/03-advanced/starter", "workshops/04-ai-era-bots/starter"],
}
STARTERS = ["workshops/01-initiation/starter", "workshops/02-proficient/starter", "workshops/03-advanced/starter", "workshops/04-ai-era-bots/starter"]


def same_tree(a, b):
    dc = filecmp.dircmp(a, b, ignore=[".venv", "instance", "__pycache__", "logs", "STARTER.json", "README.md"])
    bad = dc.left_only + dc.right_only + dc.diff_files
    for sub in dc.subdirs.values():
        bad += sub.left_only + sub.right_only + sub.diff_files
    return not bad, bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-boot", action="store_true")
    args = ap.parse_args()
    failures = 0
    print("== drift against capstones")
    for cap, targets in CAPSTONES.items():
        lab = os.path.join(ROOT, cap)
        if not os.path.exists(os.path.join(lab, "starter.manifest.json")):
            print(f"   {cap}: no starter.manifest.json yet (capstone not migrated)")
            continue
        r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "build_starter.py"), "--from", lab, "--check"], capture_output=True, text=True)
        print("   " + r.stdout.strip().replace("\n", "\n   "))
        failures += r.returncode != 0
    print("== W3 and W4 starters identical")
    w3, w4 = os.path.join(ROOT, STARTERS[2]), os.path.join(ROOT, STARTERS[3])
    if os.path.isdir(w3) and os.path.isdir(w4):
        ok, bad = same_tree(w3, w4)
        print("   identical" if ok else "   DIFFER: " + ", ".join(bad[:20]))
        failures += not ok
    else:
        print("   (not both present yet)")
    print("== contract versions")
    versions = {}
    for s in STARTERS:
        p = os.path.join(ROOT, s, "STARTER.json")
        if os.path.exists(p):
            versions[s] = json.load(open(p)).get("contract_version")
            print(f"   {s}: {versions[s]}")
    if len(set(versions.values())) > 1:
        print("   MISMATCH")
        failures += 1
    if not args.no_boot:
        print("== boot + smoke")
        for s in STARTERS:
            d = os.path.join(ROOT, s)
            if not os.path.isdir(d):
                continue
            py = os.path.join(d, ".venv", "bin", "python")
            py = py if os.path.exists(py) else sys.executable
            r = subprocess.run([py, "tools/verify.py", "--smoke"], cwd=d, capture_output=True, text=True, env=dict(os.environ, PORT="8431"))
            tail = [line for line in r.stdout.splitlines() if line.startswith(("smoke:", "  FAIL"))]
            print(f"   {s}: {'OK' if r.returncode == 0 else 'FAIL'}  " + " | ".join(tail[-5:]))
            failures += r.returncode != 0
    print("\nstarters:", "OK" if not failures else f"{failures} problem(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
