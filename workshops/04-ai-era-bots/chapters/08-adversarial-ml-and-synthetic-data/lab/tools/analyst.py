"""
Analyst plumbing: pull the store's live event log into the training history.

The store keeps its event log in Redis and wipes it on /lab/reset; the training set is
data/history/ (defenses/history.py). `pull()` is the bridge: it exports the live log
(GET /lab/ml/export), looks up who each new session REALLY was in the decision log (the simulator's
answer key, written to data/history/truth.jsonl for tools/audit.py and never read by training), and
appends both. The new sessions are tagged with the `wave` they were collected in (defenses/waves.py),
which is what lets each model train on exactly the traffic that existed at its stage.

    python tools/analyst.py                  # pull whatever the store has logged since the last pull, as wave "drop"
    python tools/analyst.py --wave poison    # ... as wave "poison"
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402  (runs the labnet guard on import)
from defenses import history, waves  # noqa: E402
from shopper import DROP  # noqa: E402


def pull(wave="drop"):
    """Append the live log to the history, tagged `wave`. Returns the number of NEW sessions."""
    before = {r["sid"] for r in history.load()["events"]}
    export = labclient.admin("GET", "/lab/ml/export")
    # The decision log has one row per gated request; the drop page is visited by every session that tries to buy.
    rows = labclient.admin("GET", "/lab/decisions", params={"path": f"/drop/{DROP}", "limit": 5000})["items"]
    truth = [{"sid": d["sid"], "actor": d["actor"]} for d in rows if d["method"] == "GET"]
    new = history.merge(export, truth)
    fresh = {r["sid"] for r in history.load()["events"]} - before
    waves.tag(fresh, wave)
    return new


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--wave", default="drop", choices=sorted({w for ws in waves.STAGES.values() for w in ws}))
    args = ap.parse_args()
    labclient.wait_for_store()
    print(f"{pull(args.wave)} new sessions appended to data/history/ as wave {args.wave!r}")
