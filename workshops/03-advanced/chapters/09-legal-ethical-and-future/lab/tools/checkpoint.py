"""
Chapter 9: catch-up checkpoints for the three rounds.

    python tools/checkpoint.py --round 1                 Round 1 answer key (the verdict table)
    python tools/checkpoint.py --round 2                 Round 2 reference scoreboard, and how to adopt the reference policy
    python tools/checkpoint.py --round 3                 Round 3 rules-of-engagement checklist (the 12 items)
    python tools/checkpoint.py --round 3 --roe my_roe.md score a drafted RoE against the checklist

Round 3 scoring is keyword matching, on purpose. It checks that a topic is
addressed, not that it is addressed well; the loophole hunt in the other
team's hands does the second part. A rule written so vaguely that nobody can
tell whether it was broken is the most common defect, and no grep finds it.
"""

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)

ROE_CHECKLIST = [
    ("authorisation", "Who authorises the engagement, in writing, and who can revoke it",
     r"authori[sz]|sign[- ]?off|permission|approv"),
    ("in-scope targets", "Exactly which hosts and ports may be attacked (own stack, assigned opponent)",
     r"in[- ]scope|scope:|targets?\b.*(host|port|127\.0\.0\.1|localhost|docker)"),
    ("out of scope", "What is explicitly off limits: other teams, organiser hosts, the internet, vendor endpoints",
     r"out[- ]of[- ]scope|off[- ]limits|not in scope|forbidden targets|never target"),
    ("prohibited techniques", "No DoS or resource exhaustion, no direct attacks on data stores, no host exploitation",
     r"(denial[- ]of[- ]service|\bdos\b|volumetric|exhaust)|(redis|postgres|database|data store).*(prohibit|forbid|not|never)|(prohibit|forbid|not|never).*(redis|postgres|database|data store)"),
    ("traffic limits", "A number: requests per second or per minute, and a time window",
     r"\d+\s*(req|request|rps|r/s|per (second|minute|min))|rate limit"),
    ("synthetic data only", "No real credentials, emails or personal data anywhere in the exercise",
     r"synthetic|fake|no real (credential|email|personal|user)|real (credential|email|data).*(never|not|prohibit)"),
    ("data handling", "What captured logs may be kept, for how long, and when they are deleted",
     r"retention|retain|delete|dispose|destroy|keep (the )?(logs?|data)"),
    ("deception limits", "Honeypots and tarpits are allowed within stated bounds; no poisoning that damages the opponent",
     r"honeypot|tarpit|decoy|poison|deception"),
    ("stop conditions", "A kill switch: who can call a stop, how, and what happens then",
     r"stop|halt|kill[- ]switch|abort|pause|cease"),
    ("disclosure", "Findings go to the opposing team by a set time; no public write-ups naming people",
     r"disclos|report(ing)? (findings|results|to the)|write[- ]?up|publish"),
    ("false-positive accountability", "The defender publishes blocked-legitimate-user numbers per cohort as part of the score",
     r"false[- ]positive|legitimate (user|traffic)|cohort|fp (rate|budget)"),
    ("referee and disputes", "Who arbitrates a dispute, and the appeal path for a contested block or a scope question",
     r"referee|arbitrat|dispute|appeal|escalat|instructor decides"),
]


def round1():
    path = os.path.join(LAB, "exercises", "round1_answer_key.md")
    with open(path) as f:
        text = f.read()
    print(text)


def round2():
    audit = os.path.join(HERE, "fp_audit.py")
    ref = os.path.join(LAB, "policies", "policy_reference.json")
    print("Round 2 reference scoreboard (policies/policy_reference.json, all five campaigns):\n")
    sys.stdout.flush()
    subprocess.run([sys.executable, audit, "--policy", ref, "--campaigns", "all"], check=True)
    print("\nTo catch up:   cp policies/policy_reference.json policies/policy.json")
    print("Then read its _comment: every weight change there is a decision about who pays.")


def round3(roe_path=None):
    if not roe_path:
        print("Round 3: a rules-of-engagement document for the Capstone must cover these 12 items.\n")
        for i, (name, what, _) in enumerate(ROE_CHECKLIST, 1):
            print(f"  {i:>2}. {name:<28} {what}")
        print("\nTemplate: exercises/round3_roe_template.md    Score a draft: checkpoint.py --round 3 --roe <file>")
        return
    with open(roe_path) as f:
        text = f.read().lower()
    covered = 0
    print(f"Scoring {roe_path} against the 12-item checklist:\n")
    for i, (name, what, pattern) in enumerate(ROE_CHECKLIST, 1):
        hit = re.search(pattern, text) is not None
        covered += hit
        print(f"  [{'x' if hit else ' '}] {i:>2}. {name:<28} {'' if hit else '<- missing: ' + what}")
    print(f"\nCovered {covered}/12. Target: 10 or more, and no loophole card left unanswered.")
    if covered < 12:
        print("Keyword matching only checks that a topic is present. The other team's loophole hunt checks whether it holds.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--round", type=int, required=True, choices=[1, 2, 3])
    ap.add_argument("--roe", help="Round 3: path to a drafted rules-of-engagement markdown file")
    args = ap.parse_args()
    {1: round1, 2: round2, 3: lambda: round3(args.roe)}[args.round]()


if __name__ == "__main__":
    main()
