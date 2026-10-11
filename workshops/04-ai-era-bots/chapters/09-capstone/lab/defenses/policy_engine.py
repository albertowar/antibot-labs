"""
W4 Ch9 Capstone — the W4 Ch8 agent-policy evaluator, unchanged (GIVEN)

This is decide() from W4 Ch8's tools/agent_audit.py, lifted into the live
store so the policy a team wrote on Day 3 is the policy the store runs on
Day 4. A policy (policies/agent_policy.json) is evaluated in this order:

  1. rules             hard decisions on one fact: {"if_signal": "agent_ua", "action": "block"}
                       or {"if_client": "cloud_agent", "action": "challenge"}
  2. weights           points per signal, summed into a score (the W2 Ch8 ladder)
  3. thresholds        challenge_at / block_at on that score
  4. declaration       {"required": true, "undeclared_agent_action": "challenge"}: an agent
                       that does not declare itself gets at least this action. Declare or pay.
  5. account_velocity  {"orders_per_hour": 4, "action": "block"}: a per-account limit
  6. exemptions        a ceiling on the action for a cohort you protect:
                       {"if_signal": "screen_reader_api", "max_action": "challenge"}

checkout_step_up ("none" | "human_confirm"), challenge_type ("pow" |
"captcha_image"), terms, appeal_path and retention_days are read by
agent_governance.py and by the store's governance endpoints.
"""

import json
import os

LAB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
POLICY_PATH = os.path.join(LAB_DIR, "policies", "agent_policy.json")
ACTIONS = ["allow", "challenge", "block"]
RANK = {a: i for i, a in enumerate(ACTIONS)}
AGENT_CLIENTS = {"local_agent", "cloud_agent", "assistive_agent"}

_cache = {"stamp": None, "policy": None}


def load_policy(path=POLICY_PATH):
    """Hot-reloaded: edit the JSON, the next checkout uses it."""
    stamp = os.stat(path).st_mtime_ns
    if _cache["stamp"] != stamp:
        with open(path) as f:
            p = json.load(f)
        p.setdefault("rules", [])
        p.setdefault("weights", {})
        p.setdefault("exemptions", [])
        p.setdefault("challenge_at", 30)
        p.setdefault("block_at", 60)
        p.setdefault("declaration", {"required": False, "undeclared_agent_action": "allow"})
        p.setdefault("account_velocity", {"orders_per_hour": 0, "action": "allow"})
        p.setdefault("checkout_step_up", "none")
        p.setdefault("challenge_type", "pow")
        p.setdefault("terms", {"acceptance": "browsewrap", "agents_clause": "silent"})
        p.setdefault("appeal_path", False)
        p.setdefault("retention_days", 365)
        _cache.update(stamp=stamp, policy=p)
    return _cache["policy"]


def _raise(action, reason, new_action, new_reason):
    if RANK[new_action] > RANK[action]:
        return new_action, new_reason
    return action, reason


def decide(row, policy):
    """Map one session row to (action, reason). Rules, score, declaration and
    velocity raise the action; exemptions cap it."""
    signals = set(row["signals"])
    score = sum(policy["weights"].get(s, 0) for s in signals)
    action, reason = "allow", "score"
    for rule in policy["rules"]:
        hit = ("if_signal" in rule and rule["if_signal"] in signals) or \
              ("if_client" in rule and rule["if_client"] == row["client"])
        if hit:
            action, reason = _raise(action, reason, rule["action"],
                                    f"rule:{rule.get('if_signal') or rule.get('if_client')}")
    if score >= policy["block_at"]:
        action, reason = _raise(action, reason, "block", f"score {score}")
    elif score >= policy["challenge_at"]:
        action, reason = _raise(action, reason, "challenge", f"score {score}")
    decl = policy["declaration"]
    if decl.get("required") and row["client"] in AGENT_CLIENTS and not row["declared"]:
        action, reason = _raise(action, reason, decl.get("undeclared_agent_action", "challenge"), "undeclared_agent")
    vel = policy["account_velocity"]
    if vel.get("orders_per_hour", 0) > 0 and row["orders_per_hour"] >= vel["orders_per_hour"]:
        action, reason = _raise(action, reason, vel.get("action", "challenge"), "velocity")
    for ex in policy["exemptions"]:
        if ex["if_signal"] in signals and RANK[action] > RANK[ex["max_action"]]:
            action, reason = ex["max_action"], f"exempt:{ex['if_signal']}"
    return action, reason, score


if __name__ == '__main__':
    p = load_policy()
    print(p["name"], decide({"signals": ["agent_ua", "no_pointer"], "client": "local_agent",
                             "declared": True, "orders_per_hour": 1}, p))
