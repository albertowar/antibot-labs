"""
Chapter 3: save your own session as a trace file (Round 0).

Reserve a pair on http://127.0.0.1:5000/drop/lab-runner-9 in your normal browser, then:

    python tools/save_trace.py --name alice            # your latest browser session
    python tools/save_trace.py --name alice --sid XYZ  # a specific session

"Your latest browser session" is the newest reservation the decision log attributes to
you: a real browser sends no lab actor label, so the store logs it as "you". Bots and
shoppers label themselves. (A tool may read that ground truth; no defense ever does.)

The file lands in tools/traces/alice.json with "source": "browser". From then on:
    - every checkpoint scores it offline at Levels 1-3 and 5: if YOUR trace gets
      blocked, that is a false positive, not a bot;
    - Round 4's replay attack uses your newest mouse trace as its source.

A phone works too (Android, over USB): see "Record a phone trace" in the README.

Privacy: the trace holds pointer coordinates and keystroke *timings*, never
key values; the form's text never reaches the collector. Still, it is a
behavioral biometric. Don't share it outside your own machine.
"""

import argparse
import json
import os

from labclient import admin

TRACES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traces")


def latest_browser_sid():
    rows = admin("GET", "/lab/decisions", params={"actor": "you", "limit": 500})["items"]
    for row in reversed(rows):                       # oldest first -> newest first
        if row.get("method") == "POST" and (row.get("path") or "").startswith("/drop/"):
            return row["sid"]
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--name", required=True, help="file name, e.g. your first name")
    ap.add_argument("--sid", default=None, help="session id (default: your latest browser reservation)")
    args = ap.parse_args()

    sid = args.sid or latest_browser_sid()
    if sid is None:
        raise SystemExit("No browser reservation found. Reserve a pair on /drop/lab-runner-9 first, in a real browser.")
    trace = admin("GET", f"/lab/behavior/trace/{sid}")
    feats = trace.pop("features")
    decision = trace.pop("decision") or {}
    trace["source"] = "browser"
    trace["name"] = args.name
    os.makedirs(TRACES, exist_ok=True)
    path = os.path.join(TRACES, f"{args.name}.json")
    with open(path, "w") as f:
        json.dump(trace, f)

    tel = trace["telemetry"]
    print(f"Saved {os.path.relpath(path)}  (session {sid[:10]}…, level {trace['level']}, "
          f"verdict {decision.get('action', '?')})")
    print(f"  pointer samples   {len(tel['pointer'])}  ({feats['pointer_kinds']})")
    print(f"  approaches        {len(feats['approaches'])}, straightness {feats['mouse_movement_straightness']}")
    print(f"  end ratios        {[a.get('end_ratio') for a in feats['approaches']]}")
    taps = [c for c in feats["clicks"] if c["kind"] == "t"]
    if taps:
        print(f"  taps              {len(taps)}, contact {[c.get('hold_ms') for c in taps]} ms, "
              f"centre offsets {[c.get('center_offset') for c in taps]} px")
        print(f"  contact geometry  {tel.get('contact', [])[:4]}")
    print(f"  keys              {feats['keys']['n_keys']} ({feats['keys']['ime_keys']} virtual-keyboard), "
          f"dwell {feats['keys']['dwell_mean']} ms, rollover {feats['keys']['rollover_ratio']}")
    print(f"  submitted after   {feats['submit_ms'] / 1000:.1f} s")


if __name__ == "__main__":
    main()
