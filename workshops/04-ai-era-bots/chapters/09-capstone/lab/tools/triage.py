"""
W4 Ch9 Capstone — triage: propose a rule from the decision log, gate it, never enforce it (from W4 Ch7)

The ops loop W4 Ch7 taught, at capstone scale and without an LLM in the request
path. It reads the decision log, finds the signal cluster a campaign shares,
and proposes ONE narrow rule. It then *gates* the proposal by replaying it
against the whole log: a candidate is only written to rules/pending.json if it
would block real bot sessions and ZERO legitimate ones (the lab-only X-Lab-Actor
ground truth is used here for measurement, the way the scoreboard uses it —
never by the live engine). A human then approves it with tools/approve.py.

The proposal step stands in for the LLM triage of W4 Ch7: deterministic here so
the checkpoint reproduces. Point it at a real model there; the gate does not
change, and that is the whole point — a model may draft, only a person ships.

    python tools/triage.py                 # propose + gate, write pending.json
    python tools/triage.py --show           # print the candidate and its gate result
"""

import argparse
import hashlib
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
from lab import BASE_URL, admin, ensure_local  # noqa: E402
from rules import PENDING_FILE, check_rule, matches  # noqa: E402

CANDIDATE_FIELDS = ("client", "egress_kind", "declared")


def _card(d):
    """The flat session card a rule evaluates, from a logged checkout decision."""
    f = d.get("features") or {}
    return {"client": d.get("client") or "browser", "egress_kind": d.get("egress_kind") or "local",
            "declared": bool((f.get("policy") or {}).get("reason", "").startswith("rule") is False and d.get("principal") in ("declared_agent", "verified_agent")),
            "signals": d.get("signals") or [], "fp_accounts": (f.get("behavior") or {}).get("fp_accounts", 0),
            "behavior_points": f.get("behavior_points", 0)}


def propose(rows):
    """Find the caught sessions that reuse a fingerprint across accounts (a farm on one
    machine) and propose one narrow AND-rule on that cluster. Fingerprint reuse is the
    signal a farm cannot shed and a real shopper never shows, so it is the one a gate
    can confirm has no legitimate victims."""
    caught = [d for d in rows if d["action"] == "checkout" and d["outcome"] in ("block", "challenge")
              and _fp_accounts(d) >= 3]
    if not caught:
        return None
    client = Counter(d.get("client") or "browser" for d in caught).most_common(1)[0][0]
    return {"when": {"all": [{"field": "client", "op": "eq", "value": client},
                            {"field": "fp_accounts", "op": "gte", "value": 3}]},
            "action": "block", "note": f"proposed from {len(caught)} caught sessions reusing a fingerprint "
                                       f"across accounts, clustering on client={client}"}


def gate(rule, rows):
    """Replay the candidate against the log. Pass only if it catches bots and blocks no legit (ground truth)."""
    try:
        check_rule({k: v for k, v in rule.items() if k in ("when", "action")})
    except ValueError as e:
        return {"decision": "reject", "reasons": [f"invalid rule: {e}"]}
    bots = legit = 0
    for d in rows:
        if d["action"] != "checkout":
            continue
        card = {"client": d.get("client") or "browser", "egress_kind": d.get("egress_kind") or "local",
                "fp_accounts": _fp_accounts(d), "signals": d.get("signals") or [], "declared": d.get("principal") in ("declared_agent", "verified_agent"),
                "account_age_days": 0, "prior_orders": 0, "ua": "", "orders_per_hour": 0, "behavior_points": 0}
        if matches({"when": rule["when"]}, card):
            if str(d.get("actor", "")).startswith("bot") or d.get("actor") in ("local_agent_farm",):
                bots += 1
            elif d.get("actor") not in ("bot", "unknown") and not str(d.get("actor", "")).startswith("bot"):
                legit += 1
    decision = "pass" if bots > 0 and legit == 0 else "reject"
    return {"decision": decision, "would_block_bots": bots, "would_block_legit": legit}


def _fp_accounts(d):
    return (d.get("features") or {}).get("fp_accounts", 0)


def rule_id(rule):
    body = json.dumps(rule.get("when"), sort_keys=True) + rule.get("action", "")
    return "r-" + hashlib.sha1(body.encode()).hexdigest()[:6]


def run(base=BASE_URL, show=False):
    ensure_local(base)
    rows = admin("GET", "/admin/decisions", params={"limit": 20000})
    cand = propose(rows)
    if not cand:
        print("triage: no caught sessions in the log; nothing to propose.")
        return None
    g = gate(cand, rows)
    cand["gate"] = g
    cand["id"] = rule_id(cand)
    doc = {"rules": [cand]}
    with open(PENDING_FILE, "w") as f:
        json.dump(doc, f, indent=2)
    conds = " AND ".join(f"{c['field']} {c['op']} {c['value']!r}" for c in cand["when"]["all"])
    print(f"triage proposed {cand['id']}: {conds} -> {cand['action']}")
    print(f"  gate: {g['decision']} (would block {g.get('would_block_bots', 0)} bot sessions, "
          f"{g.get('would_block_legit', 0)} legit)")
    print(f"  {cand['note']}")
    print("\nAn LLM may draft; only a person ships. Approve with:")
    print(f"  python tools/approve.py --approve {cand['id']} --by <your-name>")
    if show:
        print(json.dumps(cand, indent=2))
    return cand


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=BASE_URL)
    ap.add_argument("--show", action="store_true")
    a = ap.parse_args()
    run(a.url, a.show)
