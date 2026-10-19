"""
Chapter 9, Round 2: the false-positive impact audit.

Apply a policy file to the decision log and print the bill from both sides:
how much bot traffic the policy stops, and which real people it stops by
mistake. The second number is the one regulators, accessibility law and your
own customers care about, and it is the one most teams never look at per
cohort.

A policy (policies/*.json) has four parts, evaluated in this order:

  1. rules        hard decisions on one fact: {"if_signal": "tor_exit", "action": "block"}
                  or {"if_pool_type": "datacenter", "action": "block"}. Blunt, cheap,
                  and the most common source of cohort-wide false positives.
  2. weights      points per signal, summed into a score (the W2 Ch8 ladder).
  3. thresholds   challenge_at / block_at on that score.
  4. exemptions   a ceiling on the action for a cohort you have decided to
                  protect: {"if_signal": "no_pointer", "max_action": "challenge"}.
                  "allow" means never challenge or block. This is the proportionality
                  lever, and also the hole the Round 2 attacker crawls through.

Plus three facts about the deployment that change your legal exposure but
not the verdicts: challenge_type, appeal_path, retention_days (see §9.2).

What "caught" means here: a bot that is blocked or challenged. A challenge
is a cost, not a verdict (W2 Ch8): proof-of-work or a self-hosted CAPTCHA
stops lazy automation and slows the rest. A real person who is challenged
is a friction cost, reported separately from a block. A real person who is
blocked is a false positive, full stop.

Run:
    python tools/fp_audit.py --policy policies/policy_blunt.json
    python tools/fp_audit.py --policy policies/policy.json --campaigns tor_hidden,a11y_mimic
    python tools/fp_audit.py --policy policies/policy.json --campaigns all --json
"""

import argparse
import json
import os
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
LOG = os.path.join(LAB, "data", "decisions.jsonl")
WORLD = os.path.join(LAB, "data", "world.json")

ACTIONS = ["allow", "challenge", "block"]
RANK = {a: i for i, a in enumerate(ACTIONS)}
DEFAULT_CAMPAIGNS = ["scraper_dc", "scraper_resi"]
ALL_CAMPAIGNS = ["scraper_dc", "scraper_resi", "cgnat_burst", "tor_hidden", "a11y_mimic"]
FP_BUDGET = 0.02          # the Capstone rubric: no real cohort more than 2% blocked
BOT_TARGET = 0.85         # what a proportionate policy should still stop


def load_log(path=LOG):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def load_policy(path):
    with open(path) as f:
        policy = json.load(f)
    policy.setdefault("rules", [])
    policy.setdefault("exemptions", [])
    policy.setdefault("weights", {})
    policy.setdefault("challenge_at", 30)
    policy.setdefault("block_at", 60)
    return policy


def decide(row, policy, pool_types):
    """Map one request to (action, score, reason). Rules first, then the score
    ladder, then exemptions cap the result. Exemptions win on purpose: they
    are a promise to a cohort, and a promise you can override is not one."""
    signals = set(row["signals"])
    score = sum(policy["weights"].get(s, 0) for s in signals)
    action, reason = "allow", "score"
    for rule in policy["rules"]:
        hit = ("if_signal" in rule and rule["if_signal"] in signals) or \
              ("if_pool_type" in rule and pool_types.get(row["pool"]) == rule["if_pool_type"])
        if hit and RANK[rule["action"]] > RANK[action]:
            action, reason = rule["action"], f"rule:{rule.get('if_signal') or rule.get('if_pool_type')}"
    if score >= policy["block_at"] and RANK["block"] > RANK[action]:
        action, reason = "block", "score"
    elif score >= policy["challenge_at"] and RANK["challenge"] > RANK[action]:
        action, reason = "challenge", "score"
    for ex in policy["exemptions"]:
        if ex["if_signal"] in signals and RANK[action] > RANK[ex["max_action"]]:
            action, reason = ex["max_action"], f"exempt:{ex['if_signal']}"
    return action, score, reason


def audit(rows, policy, campaigns, pool_types):
    per_persona = defaultdict(Counter)
    per_campaign = defaultdict(Counter)
    reasons = Counter()
    for row in rows:
        if row["actor"] == "bot" and row["campaign"] not in campaigns:
            continue
        action, _, reason = decide(row, policy, pool_types)
        if row["actor"] == "human":
            per_persona[row["persona"]][action] += 1
            if action == "block":
                reasons[reason] += 1
        else:
            per_campaign[row["campaign"]][action] += 1
    return per_persona, per_campaign, reasons


def cohort(persona):
    """Collapse 'vpn+autofill' into the trait that drives the decision, so the
    table shows one line per protected group."""
    for t in ("tor", "a11y", "vpn", "cgnat", "privacy", "old_device", "autofill"):
        if t in persona.split("+"):
            return t
    return "typical"


def summarise(per_persona, per_campaign):
    cohorts = defaultdict(Counter)
    for persona, c in per_persona.items():
        cohorts[cohort(persona)].update(c)
    bots = Counter()
    for c in per_campaign.values():
        bots.update(c)
    return cohorts, bots


def pct(n, total):
    return 100.0 * n / total if total else 0.0


def exposure_notes(policy, cohorts):
    """Facts about the deployment that a regulator, an accessibility auditor or
    a customer with a lawyer will ask about. None of them changes a verdict;
    all of them change what the verdict costs you."""
    notes = []
    for rule in policy["rules"]:
        if rule.get("if_signal") == "tor_exit" and rule["action"] == "block":
            notes.append("hard block on tor_exit: every Tor Browser user is refused, no score involved "
                         "(journalists, abuse survivors, people behind censorship). Challenge instead.")
        if rule.get("if_pool_type") == "datacenter" and rule["action"] == "block":
            notes.append("hard block on datacenter ASNs: refuses every work-VPN and privacy-VPN user "
                         "(the 'vpn' cohort). A score weight lets other signals decide.")
    for ex in policy["exemptions"]:
        if ex["max_action"] == "allow":
            notes.append(f"exemption {ex['if_signal']} -> allow: the cohort is never even challenged, so any bot "
                         f"that shows that signal is invisible. 'challenge' keeps the protection and the proof.")
    a11y = cohorts.get("a11y", Counter())
    if pct(a11y["block"], sum(a11y.values())) > FP_BUDGET * 100:
        notes.append("keyboard-only users (a11y) are blocked above budget: WCAG 2.2 / EN 301 549 exposure "
                     "under the European Accessibility Act (in force 28 Jun 2025) and the ADA.")
    ct = policy.get("challenge_type", "pow")
    if ct == "captcha_thirdparty":
        notes.append("challenge_type captcha_thirdparty: a third party receives device data on every challenge. "
                     "You need a transfer basis and a consent story (ePrivacy Art 5(3); W1 Ch5, §9.2).")
    elif ct == "captcha_selfhosted":
        notes.append("challenge_type captcha_selfhosted: no third-party transfer, but a visual CAPTCHA still needs "
                     "an accessible alternative (WCAG 1.1.1).")
    if not policy.get("appeal_path", False):
        notes.append("appeal_path false: a blocked person has no human to reach. GDPR Art 22 and plain customer "
                     "service both expect one. Cheap to add, expensive to lack.")
    if policy.get("retention_days", 0) > 90:
        notes.append(f"retention_days {policy['retention_days']}: decision logs carry IPs and fingerprints "
                     "(personal data). Write down why you keep them that long or shorten it (data minimisation).")
    return notes


def print_report(name, policy, campaigns, cohorts, bots, per_campaign, reasons):
    total_bots = sum(bots.values())
    caught = bots["block"] + bots["challenge"]
    print(f"=== Policy: {name}   campaigns: {', '.join(campaigns)} ===")
    print(f"Bots: {total_bots}   caught {caught} ({pct(caught, total_bots):.1f}%)   "
          f"blocked {bots['block']}   challenged {bots['challenge']}   allowed {bots['allow']} "
          f"({pct(bots['allow'], total_bots):.1f}%)")
    for campaign in campaigns:
        c = per_campaign.get(campaign, Counter())
        n = sum(c.values())
        print(f"  {campaign:<14} caught {pct(c['block'] + c['challenge'], n):5.1f}%   "
              f"(block {c['block']:>3}, challenge {c['challenge']:>3}, allow {c['allow']:>3})")
    print()
    print("Real users:")
    print(f"  {'cohort':<11} {'n':>5}  {'blocked':>8}  {'challenged':>10}  {'allowed':>8}   budget")
    over = 0
    order = ["typical", "autofill", "vpn", "cgnat", "privacy", "a11y", "old_device", "tor"]
    for name_ in order:
        c = cohorts.get(name_)
        if not c:
            continue
        n = sum(c.values())
        b = pct(c["block"], n)
        flag = "OVER" if b > FP_BUDGET * 100 else "ok"
        over += flag == "OVER"
        print(f"  {name_:<11} {n:>5}  {b:7.1f}%  {pct(c['challenge'], n):9.1f}%  {pct(c['allow'], n):7.1f}%   {flag}")
    all_h = Counter()
    for c in cohorts.values():
        all_h.update(c)
    n = sum(all_h.values())
    print(f"  {'all':<11} {n:>5}  {pct(all_h['block'], n):7.1f}%  {pct(all_h['challenge'], n):9.1f}%  "
          f"{pct(all_h['allow'], n):7.1f}%")
    print()
    print(f"FP budget ({FP_BUDGET:.0%} blocked per cohort): {over} cohort(s) over budget."
          f"   Bot target ({BOT_TARGET:.0%} caught): {'met' if pct(caught, total_bots) >= BOT_TARGET * 100 else 'MISSED'}.")
    if reasons:
        print("Why real people were blocked: " + ", ".join(f"{r} {n}" for r, n in reasons.most_common()))
    notes = exposure_notes(policy, cohorts)
    print()
    print("Exposure notes (§9.2):" if notes else "Exposure notes: none.")
    for note in notes:
        print(f"  - {note}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", required=True, help="policies/*.json")
    ap.add_argument("--campaigns", default=",".join(DEFAULT_CAMPAIGNS),
                    help="comma list, or 'all' (default: %(default)s)")
    ap.add_argument("--log", default=LOG)
    ap.add_argument("--json", action="store_true", help="machine-readable summary instead of the report")
    args = ap.parse_args()
    campaigns = ALL_CAMPAIGNS if args.campaigns == "all" else args.campaigns.split(",")
    unknown = [c for c in campaigns if c not in ALL_CAMPAIGNS]
    if unknown:
        ap.error(f"unknown campaign(s) {unknown}; choose from {ALL_CAMPAIGNS}")
    with open(WORLD) as f:
        pool_types = {k: v["type"] for k, v in json.load(f)["pools"].items()}
    policy = load_policy(args.policy)
    rows = load_log(args.log)
    per_persona, per_campaign, reasons = audit(rows, policy, campaigns, pool_types)
    cohorts, bots = summarise(per_persona, per_campaign)
    name = policy.get("name", os.path.basename(args.policy))
    if args.json:
        total = sum(bots.values())
        print(json.dumps({
            "policy": name, "campaigns": campaigns,
            "bots_caught_pct": round(pct(bots["block"] + bots["challenge"], total), 1),
            "cohorts": {k: {"n": sum(v.values()), "blocked_pct": round(pct(v["block"], sum(v.values())), 1),
                            "challenged_pct": round(pct(v["challenge"], sum(v.values())), 1)}
                        for k, v in cohorts.items()},
            "exposure_notes": exposure_notes(policy, cohorts),
        }, indent=2))
    else:
        print_report(name, policy, campaigns, cohorts, bots, per_campaign, reasons)


if __name__ == "__main__":
    main()
