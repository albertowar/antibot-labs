"""
W4 Ch9 Capstone — human approval: the only writer of rules/active.json (from W4 Ch7)

triage.py drafts; a person approves. A rule reaches the live engine only when
someone with a name approved a candidate the gate passed (OWASP "Excessive
Agency": an LLM never writes an enforcement rule by itself). The same tool
onboards a trusted agent operator, because that is the other change a human
makes to the live policy on launch day (Round 4's new vendor).

    python tools/approve.py --list
    python tools/approve.py --approve r-ab12cd --by alice
    python tools/approve.py --revoke r-ab12cd --by alice
    python tools/approve.py onboard-operator --host agents.newvendor.test --by alice

active.json is written atomically and its version bumped; every change is
appended to rules/audit.jsonl. Rule notes are printed through safe_text():
they may have been drafted from attacker-controlled data.
"""

import argparse
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "defenses"))
from rules import ACTIVE_FILE, AUDIT_FILE, PENDING_FILE, check_rule  # noqa: E402

TRUSTED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "defenses", "trusted_operators.json")


def safe_text(s, n=80):
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(s))
    return s[:n]


def load(path, default):
    if os.path.exists(path):
        with open(path) as fh:
            return json.load(fh)
    return default


def save_active(doc):
    doc["version"] = doc.get("version", 0) + 1
    tmp = ACTIVE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(doc, fh, indent=2)
    os.replace(tmp, ACTIVE_FILE)


def audit(action, rule_id, by, extra=None):
    os.makedirs(os.path.dirname(AUDIT_FILE), exist_ok=True)
    with open(AUDIT_FILE, "a") as fh:
        fh.write(json.dumps({"ts": time.time(), "action": action, "rule_id": rule_id, "by": by, **(extra or {})}) + "\n")


def conds_str(rule):
    return " AND ".join(f"{c['field']} {c['op']} {c['value']!r}" for c in rule.get("when", {}).get("all", []))


def pending_index():
    return {r.get("id"): r for r in load(PENDING_FILE, {"rules": []}).get("rules", [])}


def cmd_list():
    pend = pending_index()
    active = {r.get("id") for r in load(ACTIVE_FILE, {"rules": []}).get("rules", [])}
    if not pend:
        print("no candidates (run tools/triage.py first)")
        return
    for rid, r in pend.items():
        g = r.get("gate", {})
        state = "ACTIVE" if rid in active else g.get("decision", "ungated").upper()
        print(f"  {rid}  [{state:<6}] {safe_text(conds_str(r)):<60} "
              f"(bots {g.get('would_block_bots', 0)}, legit {g.get('would_block_legit', 0)})")


def approve_one(rid, rule, by, active):
    g = rule.get("gate", {})
    if g.get("decision") != "pass":
        print(f"  refuse {rid}: the gate said {g.get('decision', 'nothing')} — a person cannot approve what the gate failed")
        return False
    try:
        check_rule({k: v for k, v in rule.items() if k in ("when", "action")})
    except ValueError as e:
        print(f"  refuse {rid}: {e}")
        return False
    if any(r.get("id") == rid for r in active["rules"]):
        print(f"  {rid} already active")
        return False
    clean = {"id": rid, "when": rule["when"], "action": rule["action"]}
    active["rules"].append(clean)
    audit("approve", rid, by, {"conds": conds_str(clean)})
    print(f"  approved {rid}: {safe_text(conds_str(clean))}  (by {by})")
    return True


def onboard_operator(host, by):
    doc = load(TRUSTED, {"trusted": []})
    if host in doc["trusted"]:
        print(f"{host} is already trusted")
        return
    doc["trusted"].append(host)
    with open(TRUSTED, "w") as fh:
        json.dump(doc, fh, indent=2)
    audit("onboard-operator", host, by)
    print(f"onboarded {host} as a trusted agent operator (by {by}). "
          f"Signed requests from it now verify; re-run the audit.")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_argument
    sub("command", nargs="?", default="", help="(blank) rule approval, or 'onboard-operator'")
    sub("--list", action="store_true")
    sub("--approve", metavar="ID")
    sub("--revoke", metavar="ID")
    sub("--host", help="onboard-operator: the operator host to trust")
    sub("--by", default=os.environ.get("USER", "analyst"))
    args = ap.parse_args()

    if args.command == "onboard-operator":
        if not args.host:
            ap.error("onboard-operator needs --host")
        onboard_operator(args.host.strip().lower(), args.by)
        return 0

    if args.list or not (args.approve or args.revoke):
        cmd_list()
        return 0

    active = load(ACTIVE_FILE, {"version": 0, "rules": []})
    if args.revoke:
        before = len(active["rules"])
        active["rules"] = [r for r in active["rules"] if r.get("id") != args.revoke]
        if len(active["rules"]) < before:
            save_active(active)
            audit("revoke", args.revoke, args.by)
            print(f"revoked {args.revoke} (active version now {active['version']})")
        else:
            print(f"{args.revoke} was not active")
        return 0

    pend = pending_index()
    if args.approve not in pend:
        print(f"no candidate {args.approve}; run tools/triage.py")
        return 1
    if approve_one(args.approve, pend[args.approve], args.by, active):
        save_active(active)
        print(f"active.json version now {active['version']} ({len(active['rules'])} rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
