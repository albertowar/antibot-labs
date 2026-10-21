"""
W4 Chapter 9 — Human approval: the only writer of rules/active.json

The gate filters candidates; a person approves them. This tool is the
human-in-the-loop that keeps an LLM out of the enforcement decision (OWASP
LLM06, Excessive Agency): a rule reaches the edge only when someone with a
name approved a candidate the gate passed.

    python tools/approve.py --list
    python tools/approve.py --approve r-ab12cd --by alice
    python tools/approve.py --all-passed --yes --by checkpoint
    python tools/approve.py --revoke r-ab12cd --by alice

active.json is written atomically (tmp + rename), its version is bumped, and
every change is appended to rules/audit.jsonl. Rejected candidates cannot be
approved. Rule descriptions are printed through safe_text(): they were
written by a model from attacker-controlled data.
"""

import argparse
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # lab root

from defenses.rules import ACTIVE_FILE, AUDIT_FILE, PENDING_FILE, check_rule
from defenses.schemas import safe_text


def _rule_id(rule):
    body = json.dumps(rule.get("when"), sort_keys=True) + rule.get("action", "")
    return "r-" + hashlib.sha1(body.encode()).hexdigest()[:6]


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
        fh.write(json.dumps({"ts": time.time(), "action": action, "rule_id": rule_id,
                             "by": by, **(extra or {})}) + "\n")


def conds_str(rule):
    return " AND ".join(f"{c['field']} {c['op']} {c['value']!r}" for c in rule.get("when", {}).get("all", []))


def pending_index():
    doc = load(PENDING_FILE, {"rules": []})
    out = {}
    for r in doc.get("rules", []):
        out[_rule_id(r)] = r
    return out


def cmd_list():
    pend = pending_index()
    active = {r.get("id") for r in load(ACTIVE_FILE, {"rules": []}).get("rules", [])}
    if not pend:
        print("no candidates (run defenses.rulesmith then defenses.rule_gate)")
        return
    for rid, r in pend.items():
        g = r.get("gate", {})
        state = "ACTIVE" if rid in active else g.get("decision", "ungated").upper()
        extra = (f"fp {g.get('fp')}/{g.get('cohort_n')} cov {g.get('coverage', 0):.0%}"
                 if "fp" in g else "")
        print(f"  {rid}  [{state:<6}] {safe_text(conds_str(r), 68):<68} {extra}")


def approve_one(rid, rule, by, active):
    g = rule.get("gate", {})
    if g.get("decision") != "pass":
        print(f"  refuse {rid}: gate said {g.get('decision', 'nothing')} ({','.join(g.get('reasons', []))})")
        return False
    try:
        check_rule(rule)
    except ValueError as e:
        print(f"  refuse {rid}: {e}")
        return False
    if any(r.get("id") == rid for r in active["rules"]):
        print(f"  {rid} already active")
        return False
    rule = {k: v for k, v in rule.items() if k != "gate"}
    rule["id"] = rid
    active["rules"].append(rule)
    audit("approve", rid, by, {"conds": conds_str(rule)})
    print(f"  approved {rid}: {safe_text(conds_str(rule), 70)}")
    return True


def main():
    ap = argparse.ArgumentParser(description="Approve gate-passed rules into active.json.")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--approve", metavar="ID")
    ap.add_argument("--all-passed", action="store_true")
    ap.add_argument("--revoke", metavar="ID")
    ap.add_argument("--by", default=os.environ.get("USER", "analyst"))
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = ap.parse_args()

    if args.list or not (args.approve or args.all_passed or args.revoke):
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
    changed = 0
    if args.approve:
        if args.approve not in pend:
            print(f"no candidate {args.approve}")
            return 1
        changed += approve_one(args.approve, pend[args.approve], args.by, active)
    if args.all_passed:
        passed = [(rid, r) for rid, r in pend.items() if r.get("gate", {}).get("decision") == "pass"]
        if not passed:
            print("no gate-passed candidates")
        if passed and not args.yes:
            print(f"About to approve {len(passed)} rules. Re-run with --yes to confirm.")
            return 0
        for rid, r in passed:
            changed += approve_one(rid, r, args.by, active)
    if changed:
        save_active(active)
        print(f"active.json version now {active['version']} ({len(active['rules'])} rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
