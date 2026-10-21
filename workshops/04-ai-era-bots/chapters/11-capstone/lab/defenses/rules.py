"""
W4 Ch11 Capstone — the rule engine: the only thing a triage proposal can become (GIVEN, from W4 Ch9)

An LLM never sits in the request path. tools/triage.py asks the (mock) model
to propose rules from the decision log; tools/approve.py lets a *named person*
move a gate-passed candidate into rules/active.json; this engine evaluates the
active rules at checkout (DEFENSE_LEVEL >= 4). Deterministic, microseconds per
checkout, auditable line by line.

The DSL is deliberately narrow (W4 Ch9):
  - 2 to 4 conditions, all must match (no OR: one rule, one reason)
  - string ops eq/ne/in/contains/startswith; numeric comparisons; bool eq;
    list `contains`
  - no regular expressions (a model-written regex is a ReDoS in your hot path)
  - actions are only `block` or `shadow`; there is no `allow`. A rule that can
    allow is a rule an injected prompt will try to write (OWASP "Excessive Agency").
"""

import json
import os
import time

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules")
ACTIVE_FILE = os.path.join(RULES_DIR, "active.json")
PENDING_FILE = os.path.join(RULES_DIR, "pending.json")
AUDIT_FILE = os.path.join(RULES_DIR, "audit.jsonl")

# The session card a checkout is reduced to. Nothing here is a lab oracle.
RULE_FIELDS = {
    "client": "str", "egress_kind": "str", "ua": "str", "declared": "bool",
    "signals": "list", "orders_per_hour": "num", "account_age_days": "num",
    "prior_orders": "num", "fp_accounts": "num", "behavior_points": "num",
}
OPS = {"str": ("eq", "ne", "in", "contains", "startswith"), "list": ("contains",),
       "num": ("eq", "lt", "lte", "gt", "gte"), "bool": ("eq",)}


class RuleError(ValueError):
    pass


def check_rule(rule):
    conds = (rule.get("when") or {}).get("all")
    if not isinstance(conds, list) or not 2 <= len(conds) <= 4:
        raise RuleError("a rule needs 2 to 4 conditions under when.all")
    if rule.get("action") not in ("block", "shadow"):
        raise RuleError(f"action must be block or shadow, not {rule.get('action')!r}")
    for c in conds:
        f, op, v = c.get("field"), c.get("op"), c.get("value")
        if f not in RULE_FIELDS:
            raise RuleError(f"unknown field {f!r}")
        t = RULE_FIELDS[f]
        if op not in OPS[t]:
            raise RuleError(f"{op!r} is not valid for {f} ({t})")
        if t in ("str", "list"):
            if op == "in":
                if not (isinstance(v, list) and v and len(v) <= 8 and all(isinstance(x, str) for x in v)):
                    raise RuleError(f"{f}: 'in' needs a list of up to 8 strings")
            elif not isinstance(v, str) or not v or len(v) > 80:
                raise RuleError(f"{f}: value must be a non-empty string of at most 80 chars")
        elif t == "num":
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                raise RuleError(f"{f}: numeric value required")
        elif t == "bool" and not isinstance(v, bool):
            raise RuleError(f"{f}: boolean value required")
    return rule


def _match_str(op, actual, v):
    actual = actual or ""
    return {"eq": actual == v, "ne": actual != v, "in": actual in v if isinstance(v, list) else False,
            "contains": v in actual, "startswith": actual.startswith(v)}.get(op, False)


def _match(cond, flat):
    f, op, v = cond["field"], cond["op"], cond["value"]
    t, actual = RULE_FIELDS[f], flat.get(f)
    if t == "str":
        return _match_str(op, actual, v)
    if t == "list":
        return any(item == v for item in (actual or []))
    if t == "bool":
        return bool(actual) is v
    if actual is None:
        return False
    return {"eq": actual == v, "lt": actual < v, "lte": actual <= v, "gt": actual > v, "gte": actual >= v}[op]


def matches(rule, flat):
    return all(_match(c, flat) for c in rule["when"]["all"])


def load_active(path=ACTIVE_FILE):
    with open(path) as fh:
        doc = json.load(fh)
    for r in doc.get("rules", []):
        check_rule(r)
    return doc


class RuleEngine:
    """Hot-reloading evaluator. A broken file keeps the previous rule set."""

    def __init__(self, path=ACTIVE_FILE):
        self.path = path
        self.rules, self.version, self._stamp, self.error = [], 0, None, None
        self.reload_if_changed()

    def reload_if_changed(self):
        try:
            st = os.stat(self.path)
            stamp = (st.st_mtime_ns, st.st_size)
        except OSError:
            return
        if stamp == self._stamp:
            return
        try:
            doc = load_active(self.path)
            self.rules, self.version, self.error = doc.get("rules", []), doc.get("version", 0), None
        except (OSError, ValueError, RuleError) as e:
            self.error = f"{e.__class__.__name__}: {e}"
        self._stamp = stamp

    def evaluate(self, flat):
        """(blocking rule or None, shadow rules matched, ms)."""
        self.reload_if_changed()
        t0 = time.perf_counter()
        hit = next((r for r in self.rules if r.get("action") == "block" and matches(r, flat)), None)
        shadow = [r["id"] for r in self.rules if r.get("action") == "shadow" and matches(r, flat)]
        return hit, shadow, (time.perf_counter() - t0) * 1000

    def describe(self):
        return {"rules": len(self.rules), "version": self.version, "error": self.error}


if __name__ == '__main__':
    eng = RuleEngine()
    print(eng.describe())
    print(eng.evaluate({"client": "local_agent", "fp_accounts": 4, "account_age_days": 0.1}))
