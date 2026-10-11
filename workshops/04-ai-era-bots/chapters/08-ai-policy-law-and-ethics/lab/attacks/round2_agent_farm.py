"""
Chapter 8, Round 2: the campaigns that hide behind the user's agent.

Round 2's first fix stops blocking agents (because, after Amazon v. Perplexity,
a shopper's agent is the shopper) and exempts everything an agent or a screen
reader trips. This script runs the three campaigns built for exactly that
policy and prints the attacker's view: how many sessions got through, and why.

    local_agent_farm          200 fresh accounts, each driving a local agentic browser.
                              Per session it is an agent shopper. Per account it places
                              6-15 orders an hour and nobody is there to confirm anything.
    declared_then_undeclared  a cloud agent that signs its requests until it is blocked,
                              then drops the signature and returns as Chrome on residential
                              addresses. Punishing the declared ones taught it that.
    a11y_mimic                no pointer events, screen-reader API calls, reused
                              fingerprints. Lives inside the exemption written for
                              assistive technology.

This is the same audit as tools/agent_audit.py with the hidden campaigns switched
on; it exists so the attack step is one command. It reads local files only and
never generates traffic: the sessions are in data/agent_sessions.jsonl, drawn
from documentation address ranges. The campaigns are models for training
defenders against their own policy, not tooling.

Run:
    python attacks/round2_agent_farm.py --policy policies/agent_policy.json
    python attacks/round2_agent_farm.py --policy policies/agent_policy_naive.json --campaigns local_agent_farm
"""

import argparse
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB, "tools"))
from agent_audit import audit, caught, load_log, load_policy, pct, print_report  # noqa: E402

HIDDEN = ["local_agent_farm", "declared_then_undeclared", "a11y_mimic"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--campaigns", default=",".join(HIDDEN), help="comma list (default: the three hidden campaigns)")
    ap.add_argument("--quiet", action="store_true", help="attacker's summary only, no scoreboard")
    args = ap.parse_args()
    if re.match(r"^\w+://", args.policy):
        sys.exit("This script reads a local policy file. It does not take a URL and never sends traffic.")
    campaigns = [c for c in args.campaigns.split(",") if c]
    unknown = [c for c in campaigns if c not in HIDDEN + ["scalper_headless"]]
    if unknown:
        ap.error(f"unknown campaign(s) {unknown}")
    policy = load_policy(args.policy)
    rows = load_log()
    per_cohort, per_campaign, reasons = audit(rows, policy, campaigns)
    print(f"=== Attacker's view vs policy '{policy.get('name')}' ===")
    for campaign in campaigns:
        c = per_campaign.get(campaign, Counter())
        n = sum(c.values())
        got = c["allowed"] + c["step_up"]
        print(f"  {campaign:<26} {got:>3}/{n} sessions reached the shop unchallenged "
              f"({pct(got, n):.0f}%); caught {pct(caught(c), n):.0f}%")
    total = sum(sum(c.values()) for c in per_campaign.values())
    allowed = sum(c["allowed"] for c in per_campaign.values())
    print(f"  Overall: {allowed}/{total} allowed. "
          + ("The exemptions are the door." if pct(allowed, total) > 50 else "Mostly stopped; read where."))
    if not args.quiet:
        print()
        print_report(policy.get("name"), policy, campaigns, per_cohort, per_campaign, reasons)


if __name__ == "__main__":
    main()
