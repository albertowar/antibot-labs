"""
Reading the decision log

Shared by every tool here. The store logs one row per gated request (instance/decisions.jsonl, the
mirror of GET /lab/decisions that has no 5000-row cap, so six weeks fit). The rows that matter are
the sign-ins: phase `action:login`, method POST. A person who meets a challenge is logged twice, the
scored attempt and the same attempt resumed after the answer (`extra.cleared`). `read_log()` folds
each session into ONE entry, the shape every tool in this chapter reads:

    sid, actor, week, clock    actor is ground truth (human:<persona>:<id> | bot:<script>), from
                               X-Lab-Actor; production never has it and no defense reads it
    ip, edge_type, cluster     the address, its network kind, the campaign cluster key
    signals                    {layer: [signal, ...]}  what every layer reported
    score, ms                  the first attempt's points and its gate time (the defender's cost)
    action                     allow | pow | step_up | block   what the engine did to the first attempt
    enforced                   the same, except that known-good traffic is decided but served
    known_good                 the monitor/QA cohort (defenses/allowlist.py)
    tel, model                 behaviour numbers; {prod|shadow|canary: {version, p, verdict}, acting}
    cred                       valid | wrong_password | unknown_user | unchecked (the password was never
                               looked at: the session did not get past its challenge)
    reached                    the session ended signed in (a 200). A proof-of-work does not stop a bot;
                               this is the business loss
    overrides                  whether operator config was in force

No defense reads `actor`: `grep -rn "actor" ../defenses` finds nothing.
"""

import json
import os
import statistics
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import labclient  # noqa: E402  (lab root on sys.path; runs the labnet guard)

BASE_URL = labclient.BASE_URL
LOGIN = ("/api/login", "/login")
ACTED = ("block", "pow", "step_up")


def server_status():
    return labclient.admin("GET", "/lab/status")


def _log_path():
    return labclient.admin("GET", "/lab/config")["decision_log"]


def read_rows():
    """Every sign-in POST the store logged, oldest first (flushes the store's buffer first)."""
    server_status()
    path = _log_path()
    if not os.path.exists(path):
        return []
    with open(path) as f:
        rows = [json.loads(line) for line in f if line.strip()]
    return [r for r in rows if r.get("phase") == "action:login" and r.get("method") == "POST"]


def fold(rows):
    """One entry per session from its sign-in rows."""
    by_sid = {}
    for r in rows:
        by_sid.setdefault(r["sid"], []).append(r)
    out = []
    for sid, rs in by_sid.items():
        first = next((r for r in rs if not (r.get("extra") or {}).get("cleared")), rs[0])
        last = rs[-1]
        x = first.get("extra") or {}
        outcome = first["outcome"]
        action = {"challenged": x.get("rung", "pow"), "deceived": "block", "blocked": "block"}.get(outcome, "allow")
        login = next((((r.get("extra") or {}).get("login"), (r.get("extra") or {}).get("login_reason")) for r in reversed(rs)
                      if (r.get("extra") or {}).get("login")), None)
        cred = x.get("cred") or ("unchecked" if login is None else "valid" if login[0] == "ok" else login[1])
        out.append({"type": "decision", "sid": sid, "actor": first["actor"], "week": x.get("week", 0),
                    "clock": x.get("clock", 0), "ip": first["ip"], "edge_type": x.get("edge_type", "unknown"),
                    "cluster": x.get("cluster"), "signals": x.get("signals") or {}, "score": first["score"],
                    "action": action, "enforced": action, "known_good": bool(x.get("known_good")),
                    "tel": x.get("tel"), "model": x.get("model") or {}, "cred": cred, "ms": first.get("ms"),
                    "overrides": bool(x.get("overrides")), "reached": last["status"] == 200,
                    "final_status": last["status"], "challenged": bool(x.get("rung")) or outcome == "challenged",
                    "contained": "asn_stepup" in (x.get("signals") or {}).get("containment", [])})
    return sorted(out, key=lambda e: (e["clock"], e["sid"]))


def read_log():
    """Every session's folded entry, in calendar order."""
    return fold(read_rows())


def decisions(entries):
    return entries


def humans(entries):
    return [e for e in entries if e["actor"].startswith("human:")]


def bots(entries):
    return [e for e in entries if e["actor"].startswith("bot:")]


def is_bot(entry):
    return entry["actor"].startswith("bot:")


def by_week(entries, week):
    return [e for e in entries if e.get("week") == week]


def persona(entry):
    return entry["actor"].split(":")[1]


def flat_signals(entry):
    return [s for sigs in entry["signals"].values() for s in sigs]


def percentiles(values):
    if not values:
        return None, None
    if len(values) < 2:
        return values[0], values[0]
    return statistics.median(values), statistics.quantiles(values, n=20)[-1]


def pct(n, total):
    return f"{100 * n / total:5.1f}%" if total else "   - "
