"""
Reading the decision log (inherited from W2 Ch8)

Shared by every tool here. The log is one JSON object per line, written by
demo_site/app.py for every scored login:

    actor      human:<persona> | bot:<script>   ground truth, from X-Lab-Actor
    week,clock the lab calendar this request belongs to (tools/weeks.py)
    signals    {layer: [signal...]}             what every sensor reported
    score      the policy score of those signals under the effective weights
    action     allow | pow | step_up | block    what the engine decided
    enforced   what actually happened (known-good traffic is decided but allowed)
    known_good bool                              the monitor/QA cohort (allowlist.py)
    model      {prod|shadow|canary: {version,p,verdict}, acting}
    tel        {pointer_events, straightness, interval_std_ms, keystrokes} | null
    cred       valid | wrong_password | unknown_user
    overrides  whether operator config was in force (defenses/config.py)
    ms         pipeline time for this request

No defense reads `actor`: `grep -rn '\bactor\b' ../defenses` finds only the
label auditor, which is a tool, not a sensor.
"""

import json
import os
import sys
import statistics
import urllib.request

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
LOG_PATH = os.environ.get("DECISION_LOG", os.path.join(LAB, "decision_log.jsonl"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))  # lab root: labnet.py
from labnet import target, require_local, require_local_env  # noqa: E402
BASE_URL = target("DEMO_URL", "http://localhost:5000")

CHALLENGES = ("pow", "step_up")


def read_log(path=LOG_PATH):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def decisions(entries):
    return [e for e in entries if e["type"] == "decision"]


def humans(entries):
    return [e for e in decisions(entries) if e["actor"].startswith("human:")]


def bots(entries):
    return [e for e in decisions(entries) if e["actor"].startswith("bot:")]


def is_bot(entry):
    return entry["actor"].startswith("bot:")


def by_week(entries, week):
    return [e for e in entries if e.get("week") == week]


def persona(entry):
    return entry["actor"].split(":", 1)[1]


def flat_signals(entry):
    return [s for sigs in entry["signals"].values() for s in sigs]


def percentiles(values):
    if not values:
        return None, None
    if len(values) < 2:
        return values[0], values[0]
    return statistics.median(values), statistics.quantiles(values, n=20)[-1]


def server_status():
    with urllib.request.urlopen(f"{BASE_URL}/lab/status", timeout=5) as r:
        return json.loads(r.read())


def server_reset():
    req = urllib.request.Request(f"{BASE_URL}/lab/reset", method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def pct(n, total):
    return f"{100 * n / total:5.1f}%" if total else "   - "
