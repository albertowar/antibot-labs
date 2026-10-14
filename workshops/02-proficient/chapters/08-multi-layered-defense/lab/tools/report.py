"""
Chapter 8: reading the decision log

Shared by checkpoint.py, layer_report.py and sweep.py. The store logs one row per gated request
(GET /lab/decisions). The rows that matter here are the logins:

    phase     action:login
    actor     human:<persona>:<id>   ground truth, from X-Lab-Actor (no defense reads it)
    action    the highest-score decision of the request (a 0-point campaign step-up reads "allow")
    outcome   served | challenged | blocked | deceived: what the client actually got
    ms        gate time for this request (the defender's cost)
    extra     signals {layer: [name, ...]}  what every layer reported (also at level 0)
              cluster, cred                 the campaign layer's key and the password outcome (level 4)
              cleared                       the challenge type this request had already solved

A challenged person logs in twice: the first row is the scored attempt, the second (extra.cleared)
is the same attempt resumed. `attempts()` keeps the first.
"""

import os
import statistics
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import labclient  # noqa: E402  (lab root on sys.path; runs the labnet guard)

LOGIN = ("/api/login", "/login")
CHALLENGES = ("challenge",)


def read_log(since=None):
    """Every login POST of the lab's human customers since `since`, oldest first."""
    rows = []
    for path in LOGIN:
        params = {"path": path, "limit": 5000, "actor": "human:"}
        if since:
            params["since"] = since
        rows += labclient.admin("GET", "/lab/decisions", params=params)["items"]
    rows = [r for r in rows if r["phase"] == "action:login" and r["method"] == "POST"]
    return sorted(rows, key=lambda r: (r["ts"], r.get("sid") or ""))


def attempts(rows):
    """The scored attempt of each login (not the retry after a solved challenge)."""
    return [r for r in rows if not (r.get("extra") or {}).get("cleared")]


def persona(row):
    return row["actor"].split(":")[1]


def layers(row):
    return (row.get("extra") or {}).get("signals") or {}


def flat_signals(row):
    return [s for names in layers(row).values() for s in names]


def percentiles(values):
    if not values:
        return None, None
    if len(values) < 2:
        return values[0], values[0]
    return statistics.median(values), statistics.quantiles(values, n=20)[-1]


def pct(n, total):
    return f"{100 * n / total:5.1f}%" if total else "   - "
