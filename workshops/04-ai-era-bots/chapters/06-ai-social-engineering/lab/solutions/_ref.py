"""Shared plumbing for the reference detectors: paths, scoring hook. Not a round on its own."""
import json
import os
import subprocess
import sys

SOL = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(SOL)
TOOLS = os.path.join(LAB, "tools")
REF = os.path.join(LAB, "out", "reference")
sys.path.insert(0, TOOLS)
sys.path.insert(0, SOL)


def path(name):
    os.makedirs(REF, exist_ok=True)
    return os.path.join(REF, name)


def score(args):
    """Run tools/score.py with args unless --no-score was given; returns nothing."""
    if "--no-score" in sys.argv:
        return
    subprocess.run([sys.executable, os.path.join(TOOLS, "score.py"), *args], check=False)
