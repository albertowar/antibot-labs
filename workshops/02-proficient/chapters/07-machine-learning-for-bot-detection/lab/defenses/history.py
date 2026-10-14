"""
The training history: the store's event log, exported and kept on disk.

The store keeps its event log in Redis and `POST /lab/reset` wipes it with the rest of the lab
state, which is what you want between rounds and not what you want from a training set. So the
training data is a file: `tools/simulate.py` generates a drop day against the running store and
appends the store's log (`GET /lab/ml/export`) here, and `tools/label_cluster.py` pulls any
attack wave you ran since. Everything under data/history/ is generated, deterministic from the
simulator's seeds, and gitignored.

    data/history/log.jsonl            one typed record per line: ev (request), tel (telemetry),
                                      login (sid -> account), acct (account -> past orders, age)
    data/history/truth.jsonl          sid -> actor: the simulator's answer key. ONLY tools/audit.py and
                                      tools/label_cluster.py's printout read it. NEVER train on it:
                                      production has no such file.
    data/history/manual_labels.jsonl  analyst decisions (tools/label_cluster.py), label 1 = bot
"""

import json
import os

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "history")
LOG = os.path.join(DIR, "log.jsonl")
TRUTH = os.path.join(DIR, "truth.jsonl")
MANUAL = os.path.join(DIR, "manual_labels.jsonl")


def exists():
    return os.path.exists(LOG) and os.path.getsize(LOG) > 0


def reset():
    for path in (LOG, TRUTH, MANUAL):
        if os.path.exists(path):
            os.remove(path)


def _read(path):
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def merge(export, truth_rows):
    """Append an export (GET /lab/ml/export) to the history, skipping sessions already in it. Returns new sessions."""
    os.makedirs(DIR, exist_ok=True)
    known = {r["sid"] for r in _read(LOG) if r["t"] == "ev"}
    known_accts = {r["account"] for r in _read(LOG) if r["t"] == "acct"}
    new = {e["sid"] for e in export["events"]} - known
    with open(LOG, "a") as fh:
        for e in export["events"]:
            if e["sid"] in new:
                fh.write(json.dumps(dict(e, t="ev")) + "\n")
        for t in export["telemetry"]:
            if t["sid"] in new:
                fh.write(json.dumps(dict(t, t="tel")) + "\n")
        for sid, account in export["logins"].items():
            if sid in new:
                fh.write(json.dumps({"t": "login", "sid": sid, "account": account}) + "\n")
        for a in export["accounts"]:
            if a["account"] not in known_accts:
                fh.write(json.dumps(dict(a, t="acct")) + "\n")
    have = {r["sid"] for r in _read(TRUTH)}
    with open(TRUTH, "a") as fh:
        for row in truth_rows:
            if row["sid"] in new and row["sid"] not in have:
                fh.write(json.dumps(row) + "\n")
                have.add(row["sid"])
    return len(new)


def load():
    """{events, telemetry, logins {sid: account}, accounts [rows]} for training. The answer key is NOT in here."""
    rows = _read(LOG)
    return {"events": [r for r in rows if r["t"] == "ev"], "telemetry": [r for r in rows if r["t"] == "tel"],
            "logins": {r["sid"]: r["account"] for r in rows if r["t"] == "login"},
            "accounts": [r for r in rows if r["t"] == "acct"]}


def manual_labels():
    """{sid: 0|1}, the latest decision per session."""
    return {r["sid"]: float(r["label"]) for r in _read(MANUAL)}


def load_truth():
    """The answer key as {sid: actor}. Lab tooling only (tools/audit.py)."""
    return {r["sid"]: r["actor"] for r in _read(TRUTH)}


def has_actors(prefix):
    return any(r["actor"].startswith(prefix) for r in _read(TRUTH))
