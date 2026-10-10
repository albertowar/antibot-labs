"""
The operations scoreboard: both sides of every week

    python tools/ops.py                 the latest week in the log
    python tools/ops.py --week 2        a specific week
    python tools/ops.py --all           every week, one row each (the five-week story)
    python tools/ops.py --watch         refresh every 2s (a terminal dashboard)

For each week it reads the decision log and reports what no single number
can tell you alone:

  Caught / missed    Treat "the stack acted" (enforced != allow) as the
                     positive class and the actor label as truth. Precision,
                     recall and the real-user false-positive rate: the three
                     numbers a detection team actually lives by.
  Bots that won      A bot whose login reached a valid password and was not
                     blocked or stepped up. A proof-of-work does not stop a
                     bot (it solves it); a deceptive block and a step-up do.
                     This is the business loss, and it is not the same as
                     recall: a model can "catch" 90% and still let the 10%
                     that matters sign in.
  Real users hurt    Customers blocked or challenged, by persona. Every one
                     is a false positive with a name.
  Known-good         The monitor cohort's false-positive rate: the only live
                     one you have, and a biased floor (allowlist.py).

The actor label is ground truth that production never has. Here it lets the
scoreboard grade the week; in production these same rows come from your
labels, with all the error Round 3 is about.
"""

import argparse
import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from report import BASE_URL, by_week, decisions, flat_signals, is_bot, pct, read_log  # noqa: E402

ACTED = ("block", "pow", "step_up")


def grade(entries):
    tp = fp = fn = tn = 0
    for e in entries:
        acted = e["enforced"] in ACTED
        if is_bot(e):
            tp += acted
            fn += not acted
        else:
            fp += acted
            tn += not acted
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall}


def bot_wins(entries):
    # A bot reaches an account when its login is valid and it was not blocked
    # or stepped up. A proof-of-work is solved, so it does not stop the bot.
    return [e for e in entries if is_bot(e) and e["cred"] == "valid"
            and e["enforced"] in ("allow", "pow")]


def fp_pct(g):
    denom = g["fp"] + g["tn"]
    return g["fp"] / denom if denom else None


def week_report(entries, week):
    es = by_week(entries, week)
    if not es:
        print(f"week {week}: nothing in the log yet")
        return
    humans = [e for e in es if not is_bot(e)]
    bots = [e for e in es if is_bot(e)]
    g = grade(es)
    wins = bot_wins(es)
    f = lambda x: "  -  " if x is None else f"{100 * x:4.0f}%"
    print(f"=== week {week}: {len(es)} logins ({len(humans)} customers, {len(bots)} bots) ===\n")
    print(f"Detection (acting on a session = positive)")
    print(f"  precision {f(g['precision'])}   recall {f(g['recall'])}   "
          f"TP {g['tp']}  FP {g['fp']}  FN {g['fn']}")
    bot_actions = Counter(e["enforced"] for e in bots)
    print(f"  bot outcomes: " + ", ".join(f"{a} {bot_actions[a]}" for a in
          ("allow", "pow", "step_up", "block") if bot_actions[a])
          + "   (a proof-of-work is solved by the bot, so 'pow' is not a stop)")
    print(f"Bots that reached an account: {len(wins)}   "
          f"(of {sum(1 for e in bots if e['cred'] == 'valid')} with a valid pair)")

    hurt = defaultdict(Counter)
    for e in humans:
        if e["enforced"] in ACTED:
            hurt[e["actor"].split(':', 1)[1]][e["enforced"]] += 1
    blocked = sum(v for c in hurt.values() for a, v in c.items() if a == "block")
    chall = sum(v for c in hurt.values() for a, v in c.items() if a != "block")
    print(f"\nReal users hurt: {blocked} blocked, {chall} challenged, of {len(humans)} "
          f"({pct(blocked + chall, len(humans)).strip()})")
    for p, actions in sorted(hurt.items(), key=lambda kv: -sum(kv[1].values())):
        print(f"  {p:<16} " + ", ".join(f"{a} {n}" for a, n in sorted(actions.items())))

    kg = [e for e in humans if e.get("known_good")]
    kg_hit = [e for e in kg if e["signals"]]
    if kg:
        fired = Counter(s for e in kg for s in flat_signals(e))
        print(f"\nKnown-good cohort: {len(kg_hit)}/{len(kg)} had a signal fire "
              f"({pct(len(kg_hit), len(kg)).strip()}); "
              + (", ".join(f"{s} {n}" for s, n in fired.most_common(4)) or "none"))


def all_weeks(entries):
    weeks = sorted({e.get("week", 0) for e in entries if e.get("week")})
    print(f"{'week':>4} {'bots':>5} {'blocked':>8} {'recall':>7} {'users hurt':>11} {'bots in':>8}")
    for w in weeks:
        es = by_week(entries, w)
        g = grade(es)
        humans = [e for e in es if not is_bot(e)]
        bots = [e for e in es if is_bot(e)]
        hurt = sum(1 for e in humans if e["enforced"] in ACTED)
        blocked = sum(1 for e in bots if e["enforced"] == "block")
        f = lambda x: "  -  " if x is None else f"{100 * x:4.0f}%"
        print(f"{w:>4} {len(bots):>5} {pct(blocked, len(bots)):>8} {f(g['recall']):>7} "
              f"{pct(hurt, len(humans)):>11} {len(bot_wins(es)):>8}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--week", type=int)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--watch", action="store_true")
    args = parser.parse_args()

    def render():
        entries = decisions(read_log())
        if not entries:
            print("No decisions logged yet. Replay a week: python tools/weeks.py --week 1")
            return
        if args.all:
            all_weeks(entries)
        else:
            week = args.week or max(e.get("week", 0) for e in entries)
            week_report(entries, week)

    if args.watch:
        try:
            while True:
                print("\033[2J\033[H", end="")
                print(f"ops.py --watch   {BASE_URL}   {time.strftime('%H:%M:%S')}\n")
                render()
                time.sleep(2)
        except KeyboardInterrupt:
            return 0
    render()
    return 0


if __name__ == "__main__":
    sys.exit(main())
