"""
The analyst's queue: label sessions a person actually looked at (Round 3-4)

Weak labels are circular (defenses/labels.py): the model that let a bot in
calls it human, and the next model learns the same mistake. The only way out
is a human eye on a small, well-chosen sample. This tool is that sample.

    python tools/label.py --queue                      sessions worth a look, ranked
    python tools/label.py --queue --week 4
    python tools/label.py --session <sid> --as bot --note "resi exit, helper mouse"
    python tools/label.py --cluster <cluster-key> --as bot --week 5
    python tools/label.py --audit                      labels vs ground truth (labels.py --audit)

The queue ranks by disagreement and surprise, because that is where a label
buys the most: sessions where shadow and prod disagree, where the model is
unsure (score near a threshold), and the whole known-good cohort. It shows
each session's signals and, because this is a lab, the actor label, so you
can label a realistic sample quickly. In production an analyst reads
sessions, not a truth column; the queue is the same, the certainty is not.

Labels are appended to data/labels.jsonl and override weak labels for the
same session in train.py and gate.py.
"""

import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "defenses"))

import labels  # noqa: E402
from report import decisions, flat_signals, read_log  # noqa: E402


def surprise(e):
    model = e.get("model") or {}
    prod, shadow = model.get("prod"), model.get("shadow")
    score = 2 if (prod and shadow and prod["verdict"] != shadow["verdict"]) else 0
    score += 1 if e.get("known_good") and e["signals"] else 0
    score += 1 if 25 <= e["score"] <= 65 else 0            # near a threshold
    score += 1 if (e["enforced"] == "allow" and e["cred"] == "valid" and flat_signals(e)) else 0
    return score


def queue(entries, week, n=20):
    pool = [e for e in entries if (week is None or e.get("week") == week)]
    ranked = sorted(pool, key=lambda e: (-surprise(e), e["sid"]))[:n]
    known = labels.analyst()
    print(f"{'sid':<26} {'wk':>2} {'actor':<18} {'enf':<8} {'score':>5} {'lab?':<6} signals")
    for e in ranked:
        sigs = ",".join(flat_signals(e)) or "-"
        print(f"{e['sid']:<26} {e.get('week', 0):>2} {e['actor']:<18} {e['enforced']:<8} "
              f"{e['score']:>5} {known.get(e['sid'], '-'):<6} {sigs[:40]}")
    print(f"\n{len(ranked)} shown. Label one: tools/label.py --session <sid> --as bot|human")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--queue", action="store_true")
    parser.add_argument("--session")
    parser.add_argument("--cluster")
    parser.add_argument("--as", dest="label", choices=["bot", "human"])
    parser.add_argument("--week", type=int)
    parser.add_argument("--note", default="")
    parser.add_argument("--audit", action="store_true")
    args = parser.parse_args()
    entries = decisions(read_log())

    if args.audit:
        for source in ("weak", "analyst", "weak+analyst"):
            labels.audit(entries, source)
        return 0
    if args.queue:
        queue(entries, args.week)
        return 0
    if args.label and (args.session or args.cluster):
        if args.session:
            targets = [e for e in entries if e["sid"] == args.session]
        else:
            targets = [e for e in entries if e.get("cluster") == args.cluster
                       and (args.week is None or e.get("week") == args.week)]
        if not targets:
            print("no matching sessions in the log")
            return 1
        labels.add([{"sid": e["sid"], "label": args.label, "source": "analyst",
                     "week": e.get("week", 0), "note": args.note} for e in targets])
        actors = Counter(e["actor"] for e in targets)
        print(f"labelled {len(targets)} session(s) as {args.label}: "
              + ", ".join(f"{a} {n}" for a, n in actors.most_common()))
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
