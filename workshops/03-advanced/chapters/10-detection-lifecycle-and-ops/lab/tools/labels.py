"""
Where labels come from, and why that is the attack surface

Nobody hands you a labelled dataset in production. You build one from your
own decisions, and that is the loop this chapter is about:

  WEAK labels, derived from outcomes you already have
    bot    the engine blocked it, or it filled the honeypot
    human  it signed in with a valid password and was not blocked, or it is
           in the known-good cohort
    None   everything else (most failed logins; a stuffer's misses look like
           a customer's typos)

  ANALYST labels, written by a person after looking (tools/label.py), stored
  in ../data/labels.jsonl as {"sid", "label", "source", "week", "note"}.
  They override weak labels for the same session.

The weak rule is circular by construction. "We let it in, so it is human"
teaches the next model to let in whatever the last one let in. An attacker
who gets through does not just win today: they relabel themselves as a
customer for every retrain that follows (Round 3). The only way out is a
sample that a human looked at, which is slow and expensive, which is why it
must be small and chosen well (disagreements, incidents, the known-good
cohort's misfires).

`--audit` compares both sources with the lab's ground truth (the actor label
only the simulator sets; this is a tool, not a defense). Production has no such column; here it
shows you how wrong "obviously fine" labels are.
"""

import argparse
import json
import os
from collections import Counter

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
LABELS_PATH = os.path.join(LAB, "data", "labels.jsonl")


def flat(entry):
    return [s for sigs in entry["signals"].values() for s in sigs]


def weak(entry):
    sigs = flat(entry)
    if entry["action"] == "block" or "honeypot_filled" in sigs:
        return "bot"
    if entry.get("known_good"):
        return "human"
    if entry["cred"] == "valid" and entry["action"] != "block":
        return "human"
    return None


def analyst():
    """{sid: label} from the analyst file."""
    if not os.path.exists(LABELS_PATH):
        return {}
    out = {}
    with open(LABELS_PATH) as f:
        for line in f:
            if line.strip():
                rec = json.loads(line)
                out[rec["sid"]] = rec["label"]
    return out


def add(records):
    os.makedirs(os.path.dirname(LABELS_PATH), exist_ok=True)
    with open(LABELS_PATH, "a") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def labelled(entries, source="weak"):
    """[(entry, label)] for the chosen source: weak | analyst | weak+analyst."""
    by_analyst = analyst() if "analyst" in source else {}
    out = []
    for e in entries:
        label = None
        if "weak" in source:
            label = weak(e)
        if e["sid"] in by_analyst:
            label = by_analyst[e["sid"]]
        if label:
            out.append((e, label))
    return out


def truth(entry):
    return "bot" if entry["actor"].startswith("bot:") else "human"


def audit(entries, source):
    rows = labelled(entries, source)
    print(f"{source}: {len(rows)}/{len(entries)} decisions labelled")
    for label in ("human", "bot"):
        got = [e for e, l in rows if l == label]
        wrong = [e for e in got if truth(e) != label]
        print(f"  labelled {label:<5} {len(got):>5}   actually the other class: {len(wrong):>4}"
              + (f"   ({', '.join(f'{a} {n}' for a, n in Counter(e['actor'] for e in wrong).most_common(3))})"
                 if wrong else ""))


if __name__ == "__main__":
    from report import decisions, read_log  # noqa: E402

    parser = argparse.ArgumentParser(description="Audit the lab's labels against ground truth")
    parser.add_argument("--audit", action="store_true")
    parser.add_argument("--weeks", default=None, help="e.g. 1-4; default all")
    args = parser.parse_args()
    entries = decisions(read_log())
    if args.weeks:
        lo, _, hi = args.weeks.partition("-")
        lo, hi = int(lo), int(hi or lo)
        entries = [e for e in entries if lo <= e.get("week", 0) <= hi]
    for source in ("weak", "analyst", "weak+analyst"):
        audit(entries, source)
