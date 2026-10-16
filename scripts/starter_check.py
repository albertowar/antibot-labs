#!/usr/bin/env python3
"""
Are the starters in sync with their manifests, and do they still honour the contract?

    python scripts/starter_check.py            # drift + contract versions + boot every starter and run its smoke test
    python scripts/starter_check.py --no-boot  # drift and versions only (fast, no venv needed)

The W1 starter is the skeleton. The W2-W4 starters are the skeleton plus each workshop's baseline,
built by scripts/build_starter.py from workshops/<NN>/starter.manifest.json.

Each starter is booted with its own .venv if present (python3.12 -m venv .venv; pip install -r requirements.txt),
otherwise with the interpreter running this script.
"""

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STARTERS = ["workshops/01-initiation/starter", "workshops/02-proficient/starter", "workshops/03-advanced/starter", "workshops/04-ai-era-bots/starter"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-boot", action="store_true")
    args = ap.parse_args()
    failures = 0
    print("== drift against manifests")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "build_starter.py"), "--all", "--check"], capture_output=True, text=True)
    print("   " + (r.stdout + r.stderr).strip().replace("\n", "\n   "))
    failures += r.returncode != 0
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

        def boot(s):
            d = os.path.join(ROOT, s)
            py = os.path.join(d, ".venv", "bin", "python")
            py = py if os.path.exists(py) else sys.executable
            env = dict(os.environ)
            env.pop("PORT", None)  # each verify.py picks its own free port, so the boots can overlap
            r = subprocess.run([py, "tools/verify.py", "--smoke"], cwd=d, capture_output=True, text=True, env=env)
            tail = [line for line in r.stdout.splitlines() if line.startswith(("smoke:", "  FAIL"))]
            return s, r.returncode, tail

        dirs = [s for s in STARTERS if os.path.isdir(os.path.join(ROOT, s))]
        with ThreadPoolExecutor(max_workers=len(dirs) or 1) as ex:
            for s, rc, tail in ex.map(boot, dirs):
                print(f"   {s}: {'OK' if rc == 0 else 'FAIL'}  " + " | ".join(tail[-5:]))
                failures += rc != 0
    print("\nstarters:", "OK" if not failures else f"{failures} problem(s)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
