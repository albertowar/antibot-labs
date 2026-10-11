"""
Chapter 3: save your own session as a trace file (Round 0).

Reserve a pair on http://localhost:5000/drop in your normal browser, then:

    python tools/save_trace.py --name alice            # your latest browser session
    python tools/save_trace.py --name alice --sid XYZ  # a specific session

The file lands in tools/traces/alice.json with "source": "browser". From
then on:
    - every checkpoint scores it at Levels 1-3: if YOUR trace gets blocked,
      that is a false positive, not a bot;
    - Round 4's replay attack uses your newest trace as its source.

Privacy: the trace holds pointer coordinates and keystroke *timings*, never
key values; form fields are stored as lengths only. Still, it is a
behavioral biometric. Don't share it outside your own machine.
"""

import argparse
import json
import os
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

TRACES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traces")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--name", required=True, help="file name, e.g. your first name")
    ap.add_argument("--sid", default="latest", help="session id (default: latest browser session)")
    args = ap.parse_args()

    r = requests.get(f"{BASE_URL}/behavior/trace/{args.sid}", params={"label": "browser"}, timeout=5)
    if r.status_code == 404:
        raise SystemExit("No browser session found. Reserve a pair on /drop first, in a real browser.")
    trace = r.json()
    feats = trace.pop("features")
    trace["source"] = "browser"
    trace["name"] = args.name
    os.makedirs(TRACES, exist_ok=True)
    path = os.path.join(TRACES, f"{args.name}.json")
    with open(path, "w") as f:
        json.dump(trace, f)

    tel = trace["telemetry"]
    print(f"Saved {os.path.relpath(path)}  (session {trace['sid']}, verdict {trace['verdict']})")
    print(f"  pointer samples   {len(tel['pointer'])}  ({feats['pointer_kinds']})")
    print(f"  approaches        {len(feats['approaches'])}, straightness {feats['mouse_movement_straightness']}")
    print(f"  end ratios        {[a.get('end_ratio') for a in feats['approaches']]}")
    print(f"  keys              {feats['keys']['n_keys']}, dwell {feats['keys']['dwell_mean']} ms, "
          f"rollover {feats['keys']['rollover_ratio']}")
    print(f"  submitted after   {feats['submit_ms'] / 1000:.1f} s")


if __name__ == "__main__":
    main()
