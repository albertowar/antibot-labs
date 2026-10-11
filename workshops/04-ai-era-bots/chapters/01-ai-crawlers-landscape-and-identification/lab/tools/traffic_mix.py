"""Generate one round's traffic mix without judging it: humans, welcome bots, and
the round's attacker, all at once, so you can read the log the way an on-call engineer
would (Round 0), then look at the scoreboard.

    python tools/traffic_mix.py --round 0
    python tools/scoreboard.py
    curl -s 'http://127.0.0.1:5000/lab/log?n=40' | python -m json.tool
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "attacks"))
sys.path.insert(0, HERE)
from _common import BASE_URL, require_local  # noqa: E402
import checkpoint  # noqa: E402
import legit_traffic  # noqa: E402

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, choices=[0, 1, 2, 3, 4], default=0)
    ap.add_argument("--url", default=BASE_URL)
    a = ap.parse_args()
    require_local(a.url)
    requests.post(f"{a.url}/lab/reset", timeout=5)
    legit_traffic.summarize(legit_traffic.run(a.url))
    print()
    mod_name = checkpoint.ATTACKS[min(a.round, 3)][0]
    importlib.import_module(mod_name).run(base=a.url)
    print(f"\nNow read the raw log: curl -s '{a.url}/lab/log?n=60' | python -m json.tool")
    print("and the decisions:   python tools/scoreboard.py")
