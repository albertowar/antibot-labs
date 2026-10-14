"""
Analyst plumbing: pull the store's live event log into the training history.

The store keeps its event log in Redis and wipes it on /lab/reset; the training set is
data/history/ (defenses/history.py). `pull()` is the bridge: it exports the live log
(GET /lab/ml/export), looks up who each new session REALLY was in the decision log (the simulator's
answer key, written to data/history/truth.jsonl for tools/audit.py and never read by training), and
appends both.

    python tools/analyst.py        # pull whatever the store has logged since the last pull
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402  (runs the labnet guard on import)
from defenses import history  # noqa: E402
from shopper import DROP  # noqa: E402


def pull():
    """Append the live log to the history. Returns the number of NEW sessions."""
    export = labclient.admin("GET", "/lab/ml/export")
    # The decision log has one row per gated request; the drop page is visited by every session that tries to buy.
    rows = labclient.admin("GET", "/lab/decisions", params={"path": f"/drop/{DROP}", "limit": 5000})["items"]
    truth = [{"sid": d["sid"], "actor": d["actor"]} for d in rows if d["method"] == "GET"]
    return history.merge(export, truth)


if __name__ == "__main__":
    labclient.wait_for_store()
    print(f"{pull()} new sessions appended to data/history/")
