"""
Chapter 10: catch-up checkpoints for the three rounds.

    python tools/checkpoint.py --round 1                     Round 1: the fleet key, and the reference stack's scoreboard
    python tools/checkpoint.py --round 2                     Round 2: the reference agent policy's scoreboard, and how to adopt it
    python tools/checkpoint.py --round 3                     Round 3: the 12 items an AI governance record must cover
    python tools/checkpoint.py --round 3 --record my.md      score a drafted governance record against the checklist

Round 3 scoring is keyword matching, on purpose. It checks that a topic is
addressed, not that it is addressed well; the audit cards
do the second part. A record that says "we comply with applicable law"
under every heading is the most common defect, and no grep finds it.
"""

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)

RECORD_CHECKLIST = [
    ("role", "Provider or deployer of each AI component; which models are third-party / GPAI downstream",
     r"deployer|provider|downstream|third[- ]party model|vendor model|gpai"),
    ("purpose and risk class", "What the system decides, and the documented Annex III / Art 6(3) assessment",
     r"annex iii|art(icle)?\.? ?6\(3\)|high[- ]risk|risk class|not high|profil"),
    ("lawful basis", "Lawful basis for telemetry AND for training the detector on it (purpose compatibility)",
     r"legitimate interest|lawful basis|art(icle)?\.? ?6|purpose (compatib|limitation)|consent"),
    ("synthetic data provenance", "Where synthetic training data came from, what the generator saw, re-identification check",
     r"synthetic|generator|ctgan|re-?identif|provenance"),
    ("transparency", "Where an AI system interacts with a person (challenge, appeal chat), it says so (Art 50)",
     r"art(icle)?\.? ?50|disclos|transparen|tell(s)? the user|labell?ed|you are talking to"),
    ("automated decisions and appeal", "Who reviews a contested block, how to reach them, and in what time (Art 22)",
     r"appeal|art(icle)?\.? ?22|human review|contest|reinstat"),
    ("human oversight", "Who can override or switch off the model, shadow mode, kill switch",
     r"oversight|override|kill[- ]switch|shadow mode|switch(ed)? off|disable|on[- ]call"),
    ("logging and retention", "What is logged (decision, model version, prompt) and for how long: a number of days",
     r"\d+\s*(days|day|hours|months|weeks)|retention (period )?of \d+"),
    ("evaluation and red team", "Adversarial tests, false positives per cohort, drift monitoring, before and after release",
     r"red[- ]team|adversarial|evaluat|false[- ]positive|cohort|drift"),
    ("third-party models and prompts", "What data leaves to a vendor model, prompt-injection controls, prompt change control",
     r"prompt|vendor|api key|data (sent|leaves|shared)|injection|system prompt"),
    ("deception limits", "Tarpits, labyrinths and decoys: who may be served them, what never leaves the lab, no targeting people",
     r"tarpit|labyrinth|decoy|honeypot|poison|deception"),
    ("incidents and complaints", "Who handles an incident, a complaint or a regulator contact (AI Office, DPA), and within how long",
     r"incident|complaint|regulator|ai office|supervisory authority|\bdpa\b|within \d+|hours|business days"),
]


def round1():
    key = os.path.join(LAB, "exercises", "round1_fleet_key.md")
    with open(key) as f:
        print(f.read())
    audit = os.path.join(HERE, "reservation_audit.py")
    ref = os.path.join(LAB, "defenses", "reservation_reference")
    print("\nRound 1 reference scoreboard (defenses/reservation_reference, full fleet):\n")
    sys.stdout.flush()
    subprocess.run([sys.executable, audit, "--stack", ref, "--fleet", "all"], check=True)
    print("\nTo catch up:   cp defenses/reservation_reference/* defenses/reservation/")
    print("Then read robots.txt there: access rules and usage preferences are different lines on purpose.")


def round2():
    audit = os.path.join(HERE, "agent_audit.py")
    ref = os.path.join(LAB, "policies", "agent_policy_reference.json")
    print("Round 2 reference scoreboard (policies/agent_policy_reference.json, all four campaigns):\n")
    sys.stdout.flush()
    subprocess.run([sys.executable, audit, "--policy", ref, "--campaigns", "all"], check=True)
    print("\nTo catch up:   cp policies/agent_policy_reference.json policies/agent_policy.json")
    print("Then read its _comment: nothing there is blocked for being an agent.")


def round3(record_path=None):
    if not record_path:
        print("Round 3: an AI governance record for the detection stack must cover these 12 items.\n")
        for i, (name, what, _) in enumerate(RECORD_CHECKLIST, 1):
            print(f"  {i:>2}. {name:<32} {what}")
        print("\nTemplate: exercises/round3_governance_record_template.md    Score a draft: checkpoint.py --round 3 --record <file>")
        return
    with open(record_path) as f:
        text = f.read().lower()
    covered = 0
    print(f"Scoring {record_path} against the 12-item checklist:\n")
    for i, (name, what, pattern) in enumerate(RECORD_CHECKLIST, 1):
        hit = re.search(pattern, text) is not None
        covered += hit
        print(f"  [{'x' if hit else ' '}] {i:>2}. {name:<32} {'' if hit else '<- missing: ' + what}")
    print(f"\nCovered {covered}/12. Target: 10 or more, and no audit card left unanswered.")
    if covered < 12:
        print("Keyword matching only checks that a topic is present. The audit cards check whether it holds.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--round", type=int, required=True, choices=[1, 2, 3])
    ap.add_argument("--record", help="Round 3: path to a drafted governance record (markdown)")
    args = ap.parse_args()
    {1: round1, 2: round2, 3: lambda: round3(args.record)}[args.round]()


if __name__ == "__main__":
    main()
