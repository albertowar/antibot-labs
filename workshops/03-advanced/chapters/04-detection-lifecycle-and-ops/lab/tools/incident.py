"""
Pre-fill an incident report from the log (Round 4)

Reads the decision log for a week and writes incident/incident_report.md
with the parts a machine can know: when the attack started, how long before
the business metric moved, which signals fired and which missed, the
infrastructure the sessions came from, and the real users containment cost.
You write the judgement: root cause, remediation, follow-ups.

    python tools/incident.py --week 5 --id INC-2026-05

It uses the lab's ground truth to describe the attack precisely; in
production you would describe what your labels and your analysts concluded,
which is the same report with honest uncertainty in the attack section.
"""

import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
from report import by_week, decisions, flat_signals, is_bot, read_log  # noqa: E402

OUT = os.path.join(LAB, "incident", "incident_report.md")
ACTED = ("block", "pow", "step_up")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--week", type=int, required=True)
    parser.add_argument("--id", default="INC-2026-01")
    args = parser.parse_args()
    es = by_week(decisions(read_log()), args.week)
    if not es:
        print(f"no decisions for week {args.week}")
        return 1
    bots = [e for e in es if is_bot(e)]
    humans = [e for e in es if not is_bot(e)]
    wins = [e for e in bots if e["cred"] == "valid" and e["enforced"] in ("allow", "pow")]
    missed = [e for e in bots if e["enforced"] == "allow"]
    first_bot = min((e for e in bots), key=lambda e: e.get("clock", 0), default=None)
    pools = Counter(e.get("pool") for e in bots)
    bot_sigs = Counter(s for e in bots for s in flat_signals(e))
    hurt = [e for e in humans if e["enforced"] in ACTED]
    hurt_personas = Counter(e["actor"].split(":", 1)[1] for e in hurt)

    lines = [f"# Incident Report {args.id}", "",
             f"*Auto-filled from the decision log for lab week {args.week}. "
             f"Replace every <...> with your judgement.*", "",
             "## SUMMARY", "<two or three sentences>", "",
             "## DETECTION",
             f"- Attack began around lab clock {first_bot.get('clock') if first_bot else '?'} "
             f"(week {args.week}).",
             f"- Bot sessions this week: {len(bots)}. Reached a valid account: {len(wins)}. "
             f"Not acted on at all: {len(missed)}.",
             f"- Signals that fired on the attack: "
             + (", ".join(f"{s} {n}" for s, n in bot_sigs.most_common(6)) or "none") + ".",
             f"- Signals that missed: the sessions above show how little fired; "
             f"name the burned/blind signal here.",
             "- Lag from first attack session to the alert that caught it: <fill in from ops.py / alerts.py>.",
             "", "## ATTACK PROFILE",
             f"- Volume: {len(bots)} sessions, {len(wins)} accounts reached.",
             f"- Infrastructure (pools): " + ", ".join(f"{p} {n}" for p, n in pools.most_common()) + ".",
             "- Evasion: <what changed from the previous week>.",
             "", "## CONTAINMENT (and its cost)",
             f"- Real users blocked or challenged this week: {len(hurt)} of {len(humans)}"
             + (": " + ", ".join(f"{p} {n}" for p, n in hurt_personas.most_common()) if hurt else "") + ".",
             "- Actions taken, each with a timestamp and a TTL: <tools/contain.py ...>.",
             "", "## LABELS PRODUCED",
             "- Sessions a person labelled: <count> (tools/label.py).",
             "", "## REMEDIATION",
             "- Short term: <re-weight / refresh corpus / threshold>.",
             "- Long term: <new signal; retrain gated on the labelled set>.",
             "", "## FALSE-POSITIVE IMPACT",
             f"- {len(hurt)} legitimate users affected this week (see personas above).",
             "", "## FOLLOW-UPS", "- [ ] <owner> <action> <by when>", ""]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, "w").write("\n".join(lines))
    print(f"wrote {OUT} ({len(bots)} bot sessions, {len(wins)} accounts reached, "
          f"{len(hurt)} real users hurt). Now write the <...> parts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
