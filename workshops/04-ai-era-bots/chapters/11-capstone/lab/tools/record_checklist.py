"""
W4 Ch11 Capstone — the 12-item AI governance record checklist (from W4 Ch10)

Keyword matching, on purpose: it checks that a topic is addressed, not that it
is addressed well. The audit cards (exercises/audit_cards.md, and the live
checks in tools/audit.py) do the second part. A record that says "we comply
with applicable law" under every heading scores well here and fails the cards.
"""

import re

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


def score_record(path):
    with open(path) as f:
        text = f.read().lower()
    rows = [(name, what, re.search(pattern, text) is not None) for name, what, pattern in RECORD_CHECKLIST]
    return rows, sum(hit for _, _, hit in rows)
