"""
Preserve the evidence before it rolls over (Round 4)

The most time-sensitive thing in an incident is not the fix, it is the
evidence: logs roll, counters expire, and the sessions you most want to
study are gone by morning. This copies the forensic set for a window into
data/snapshots/<label>/:

    the decision-log lines for the window (full, not summarised)
    the ground-truth rows for the window (data/truth.jsonl)
    the effective config and corpus state at snapshot time
    a short manifest (when, which weeks, counts)

    python tools/snapshot.py --week 5 --label inc-2026-05
    python tools/snapshot.py --label inc-2026-05           (all weeks in the log)

In production this is a BGSAVE of the session store, the raw access logs for
the window, and a dump of the Prometheus series; the shape is the same. The
labelled sessions you extract from a snapshot are the highest-value training
data you will ever get, because they are exactly today's adversary.
"""

import argparse
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
from report import decisions, read_log  # noqa: E402

SNAP_DIR = os.path.join(LAB, "data", "snapshots")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--label", required=True)
    parser.add_argument("--week", type=int, help="only this week (default: everything in the log)")
    args = parser.parse_args()

    entries = decisions(read_log())
    if args.week is not None:
        entries = [e for e in entries if e.get("week") == args.week]
    if not entries:
        print("nothing to snapshot (log empty or week not present)")
        return 1
    out = os.path.join(SNAP_DIR, args.label)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "decisions.jsonl"), "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    for name in ("truth.jsonl", "labels.jsonl", "ops_config.json", "world_updates.json"):
        src = os.path.join(LAB, "data", name)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(out, name))
    manifest = {"label": args.label, "captured": time.strftime("%Y-%m-%d %H:%M:%S"),
                "week": args.week, "decisions": len(entries),
                "weeks_present": sorted({e.get("week", 0) for e in entries})}
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"snapshot {args.label}: {len(entries)} decisions -> {out}")
    print("  " + ", ".join(f"{k} {v}" for k, v in manifest.items() if k not in ("captured", "label")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
