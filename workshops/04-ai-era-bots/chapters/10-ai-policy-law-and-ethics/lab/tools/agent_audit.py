"""
Chapter 10, Round 2: the agent-policy audit.

Apply an agent policy to the session log and print the bill from both sides:
how much of the agent-driven scalping it stops, and which real people it stops
by mistake. Since Amazon v. Perplexity (9th Cir., 4 Aug 2026) the second number
also decides which legal lever you have left: a user's local agent is the user,
so "unauthorised access" does not reach it; your terms and your technical
controls do, and only if they were written for agents.

A policy (policies/agent_policy*.json) is evaluated in this order:

  1. rules             hard decisions on one fact: {"if_signal": "agent_ua", "action": "block"}
                       or {"if_client": "cloud_agent", "action": "challenge"}.
  2. weights           points per signal, summed into a score (the W2 Ch8 ladder).
  3. thresholds        challenge_at / block_at on that score.
  4. declaration       {"required": true, "undeclared_agent_action": "challenge"}: an agent
                       that does not declare itself (agent UA token or Web Bot Auth
                       signature, W4 Ch2) gets at least this action. Declare or pay.
  5. account_velocity  {"orders_per_hour": 4, "action": "block"}: a per-account limit. The
                       farm's 200 accounts each place orders; a shopper's agent places one.
  6. checkout_step_up  "none" | "human_confirm": every non-blocked session that reaches
                       checkout gets a confirmation step a person must answer, whatever
                       the score said. A shopper's agent hands it back to the shopper; an
                       unattended farm fails it; a farm with a human operator passes it.
  7. exemptions        a ceiling on the action for a cohort you protect:
                       {"if_signal": "screen_reader_api", "max_action": "challenge"}.
                       "allow" means never challenged; it is also the hole.

Plus the facts that change your exposure, not the verdicts: challenge_type
("pow" is accessible; "captcha_image" is not), terms (acceptance and the agents
clause: "prohibited" | "declared_only" | "silent"), appeal_path, retention_days.

What "caught" means: a bot session that is blocked, challenged, or stopped at
the human step-up. A challenge is a cost, not a verdict (W2 Ch8). A real person
who is challenged is friction; a real person who is blocked is a false
positive. A screen-reader user who gets an image CAPTCHA is counted as blocked,
because they are.

Run:
    python tools/agent_audit.py --policy policies/agent_policy_blunt.json
    python tools/agent_audit.py --policy policies/agent_policy.json --campaigns local_agent_farm,a11y_mimic
    python tools/agent_audit.py --policy policies/agent_policy.json --campaigns all --json
"""

import argparse
import json
import os
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
LOG = os.path.join(LAB, "data", "agent_sessions.jsonl")

ACTIONS = ["allow", "challenge", "block"]
RANK = {a: i for i, a in enumerate(ACTIONS)}
AGENT_CLIENTS = {"local_agent", "cloud_agent", "assistive_agent"}
DEFAULT_CAMPAIGNS = ["scalper_headless"]
ALL_CAMPAIGNS = ["scalper_headless", "local_agent_farm", "declared_then_undeclared", "a11y_mimic"]
COHORT_ORDER = ["shopper", "vpn", "agent_shopper", "cloud_signed", "cloud_undeclared", "a11y_agent"]
FP_BUDGET = 0.02
BOT_TARGET = 0.85


def load_log(path=LOG):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def load_policy(path):
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
    return p


def _raise(action, reason, new_action, new_reason):
    if RANK[new_action] > RANK[action]:
        return new_action, new_reason
    return action, reason


def decide(row, policy):
    """Map one session to (action, step_up, reason). Rules, score, declaration and
    velocity raise the action; exemptions cap it; the checkout step-up is recorded
    separately because it is answered by a person, not a score."""
    signals = set(row["signals"])
    score = sum(policy["weights"].get(s, 0) for s in signals)
    action, reason = "allow", "score"
    for rule in policy["rules"]:
        hit = ("if_signal" in rule and rule["if_signal"] in signals) or \
              ("if_client" in rule and rule["if_client"] == row["client"])
        if hit:
            action, reason = _raise(action, reason, rule["action"], f"rule:{rule.get('if_signal') or rule.get('if_client')}")
    if score >= policy["block_at"]:
        action, reason = _raise(action, reason, "block", "score")
    elif score >= policy["challenge_at"]:
        action, reason = _raise(action, reason, "challenge", "score")
    decl = policy["declaration"]
    if decl.get("required") and row["client"] in AGENT_CLIENTS and not row["declared"]:
        action, reason = _raise(action, reason, decl.get("undeclared_agent_action", "challenge"), "undeclared_agent")
    vel = policy["account_velocity"]
    if vel.get("orders_per_hour", 0) > 0 and row["orders_per_hour"] >= vel["orders_per_hour"]:
        action, reason = _raise(action, reason, vel.get("action", "challenge"), "velocity")
    for ex in policy["exemptions"]:
        if ex["if_signal"] in signals and RANK[action] > RANK[ex["max_action"]]:
            action, reason = ex["max_action"], f"exempt:{ex['if_signal']}"
    step_up = policy["checkout_step_up"] != "none" and row["checkout"] and action != "block"
    return action, step_up, reason


def outcome(row, action, step_up, policy):
    """What happened to this session, from each side's point of view."""
    if action == "block":
        return "blocked"
    if action == "challenge" and policy["challenge_type"] == "captcha_image" and "screen_reader_api" in row["signals"]:
        return "blocked"                # an image CAPTCHA is a wall for a screen-reader user
    if step_up:                         # a person has to answer this one, whatever the score said
        return "step_up" if row["human_present"] else "stopped_at_step_up"
    if action == "challenge":
        return "challenged"
    return "allowed"


def audit(rows, policy, campaigns):
    per_cohort = defaultdict(Counter)
    per_campaign = defaultdict(Counter)
    reasons = Counter()
    for row in rows:
        if row["actor"] == "bot" and row["campaign"] not in campaigns:
            continue
        action, step_up, reason = decide(row, policy)
        out = outcome(row, action, step_up, policy)
        if row["actor"] == "human":
            per_cohort[row["cohort"]][out] += 1
            if out == "blocked":
                reasons[reason] += 1
        else:
            per_campaign[row["campaign"]][out] += 1
    return per_cohort, per_campaign, reasons


def pct(n, total):
    return 100.0 * n / total if total else 0.0


def caught(c):
    return c["blocked"] + c["challenged"] + c["stopped_at_step_up"]


def exposure_notes(policy, per_cohort):
    """Facts a court, a regulator or an accessibility auditor will ask about. None
    of them changes a verdict; all of them change what the verdict costs you."""
    notes = []
    terms = policy["terms"]
    hard = {r.get("if_signal") or r.get("if_client"): r["action"] for r in policy["rules"]}
    agent_blocks = [k for k, v in hard.items() if v == "block" and k in ("agent_ua", "signature_agent", "no_pointer", "local_agent", "assistive_agent", "cloud_agent")]
    if agent_blocks:
        notes.append(f"hard block on {', '.join(agent_blocks)}: after Amazon v. Perplexity (9th Cir. 2026) a shopper's "
                     "local agent is the shopper. You are refusing customers, not intruders, and the CFAA is not "
                     "the lever anyway. Challenge, declare-or-pay, or step up at checkout instead.")
    if hard.get("signature_agent") == "block":
        notes.append("hard block on signature_agent: you block the only agents you can identify, attribute and hold "
                     "to their terms (W4 Ch2), while the unsigned ones walk in. Incentive inverted.")
    if hard.get("no_pointer") == "block" or hard.get("assistive_agent") == "block":
        notes.append("hard block on no_pointer / assistive agents: keyboard and screen-reader users, with or without "
                     "an agent, are refused. EAA / EN 301 549 / ADA exposure .")
    for ex in policy["exemptions"]:
        if ex["max_action"] == "allow":
            notes.append(f"exemption {ex['if_signal']} -> allow: never challenged, so any farm that shows that signal "
                         "is invisible. 'challenge' keeps the protection and the proof.")
    if terms.get("agents_clause") == "prohibited":
        notes.append("terms prohibit agents outright: unenforceable against the assistive ones, and no path for the "
                     "declared ones you want. 'declared_only' gives you a contract term the signed agents accepted.")
    if terms.get("agents_clause") == "silent":
        notes.append("terms say nothing about agents: the contract lever that Amazon v. Perplexity left you is unused.")
    if terms.get("acceptance") != "clickwrap":
        notes.append("terms are browsewrap: visitors, and their agents, are not bound (Meta v. Bright Data).")
    decl = policy["declaration"]
    if decl.get("required") and decl.get("undeclared_agent_action") == "allow":
        notes.append("declaration required but undeclared agents are allowed: a rule with no consequence.")
    if policy["checkout_step_up"] == "none":
        notes.append("no human step-up at checkout: an agent can spend money with nobody confirming. Agentic-commerce "
                     "disputes (who authorised this order?) land on you.")
    if policy["challenge_type"] == "captcha_image":
        notes.append("challenge_type captcha_image: no non-visual path; every challenged screen-reader session is a "
                     "block (counted as one above). Use proof-of-work or an accessible confirmation.")
    if not policy.get("appeal_path", False):
        notes.append("appeal_path false: a blocked person, or their agent's owner, has no human to reach (GDPR Art 22).")
    if policy.get("retention_days", 0) > 90:
        notes.append(f"retention_days {policy['retention_days']}: session logs carry addresses and fingerprints; write down why.")
    a11y = per_cohort.get("a11y_agent", Counter())
    if pct(a11y["blocked"], sum(a11y.values())) > FP_BUDGET * 100:
        notes.append("a11y_agent blocked above budget: see the accessibility notes above; this is the cohort an "
                     "auditor measures first.")
    return notes


def print_report(name, policy, campaigns, per_cohort, per_campaign, reasons):
    bots = Counter()
    for c in per_campaign.values():
        bots.update(c)
    total = sum(bots.values())
    print(f"=== Agent policy: {name}   campaigns: {', '.join(campaigns)} ===")
    print(f"Bots: {total}   caught {caught(bots)} ({pct(caught(bots), total):.1f}%)   blocked {bots['blocked']}   "
          f"challenged {bots['challenged']}   stopped at step-up {bots['stopped_at_step_up']}   "
          f"allowed {bots['allowed']} ({pct(bots['allowed'], total):.1f}%)")
    for campaign in campaigns:
        c = per_campaign.get(campaign, Counter())
        n = sum(c.values())
        print(f"  {campaign:<26} caught {pct(caught(c), n):5.1f}%   (block {c['blocked']:>3}, challenge {c['challenged']:>3}, "
              f"step-up {c['stopped_at_step_up']:>3}, allow {c['allowed']:>3})")
    print()
    print("Real people:")
    print(f"  {'cohort':<17} {'n':>5}  {'blocked':>8}  {'challenged':>10}  {'step-up':>8}  {'allowed':>8}   budget")
    over = 0
    for cohort in COHORT_ORDER:
        c = per_cohort.get(cohort)
        if not c:
            continue
        n = sum(c.values())
        b = pct(c["blocked"], n)
        flag = "OVER" if b > FP_BUDGET * 100 else "ok"
        over += flag == "OVER"
        print(f"  {cohort:<17} {n:>5}  {b:7.1f}%  {pct(c['challenged'], n):9.1f}%  {pct(c['step_up'], n):7.1f}%  "
              f"{pct(c['allowed'], n):7.1f}%   {flag}")
    all_h = Counter()
    for c in per_cohort.values():
        all_h.update(c)
    n = sum(all_h.values())
    print(f"  {'all':<17} {n:>5}  {pct(all_h['blocked'], n):7.1f}%  {pct(all_h['challenged'], n):9.1f}%  "
          f"{pct(all_h['step_up'], n):7.1f}%  {pct(all_h['allowed'], n):7.1f}%")
    print()
    print(f"FP budget ({FP_BUDGET:.0%} blocked per cohort): {over} cohort(s) over budget.   "
          f"Bot target ({BOT_TARGET:.0%} caught): {'met' if pct(caught(bots), total) >= BOT_TARGET * 100 else 'MISSED'}.")
    if reasons:
        print("Why real people were blocked: " + ", ".join(f"{r} {n}" for r, n in reasons.most_common()))
    notes = exposure_notes(policy, per_cohort)
    print()
    print("Exposure notes (§10.2):" if notes else "Exposure notes: none.")
    for note in notes:
        print(f"  - {note}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", required=True, help="policies/agent_policy*.json")
    ap.add_argument("--campaigns", default=",".join(DEFAULT_CAMPAIGNS), help="comma list, or 'all' (default: %(default)s)")
    ap.add_argument("--log", default=LOG)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    campaigns = ALL_CAMPAIGNS if args.campaigns == "all" else args.campaigns.split(",")
    unknown = [c for c in campaigns if c not in ALL_CAMPAIGNS]
    if unknown:
        ap.error(f"unknown campaign(s) {unknown}; choose from {ALL_CAMPAIGNS}")
    policy = load_policy(args.policy)
    rows = load_log(args.log)
    per_cohort, per_campaign, reasons = audit(rows, policy, campaigns)
    name = policy.get("name", os.path.basename(args.policy))
    if args.json:
        bots = Counter()
        for c in per_campaign.values():
            bots.update(c)
        total = sum(bots.values())
        print(json.dumps({
            "policy": name, "campaigns": campaigns,
            "bots_caught_pct": round(pct(caught(bots), total), 1),
            "cohorts": {k: {"n": sum(v.values()), "blocked_pct": round(pct(v["blocked"], sum(v.values())), 1),
                            "challenged_pct": round(pct(v["challenged"], sum(v.values())), 1),
                            "step_up_pct": round(pct(v["step_up"], sum(v.values())), 1)}
                        for k, v in per_cohort.items()},
            "exposure_notes": exposure_notes(policy, per_cohort),
        }, indent=2))
    else:
        print_report(name, policy, campaigns, per_cohort, per_campaign, reasons)


if __name__ == "__main__":
    main()
