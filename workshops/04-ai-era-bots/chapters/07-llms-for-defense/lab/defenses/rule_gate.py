"""
W4 Chapter 7 — The gate  [STUDENT FILE]

A drafted rule is a claim. The gate is the experiment that tests it before
it can block anyone, by replaying it against the customers you already trust
(sessionize.verified_sids) and the sessions it is meant to catch.

Until you implement decide(), the stub passes every candidate. Run the bait
attack, approve what the stub passes, switch to DEFENSE_LEVEL=2, and watch
real VPN and privacy-browser customers get blocked by the rule the model
drafted. Then come back and write the gate.
"""

import argparse
import json
import os
import sys

from .rules import PENDING_FILE, check_rule, matches
from .sessionize import card_for_sid, flatten, verified_sids
from .rule_store import make_engine, verdicts_t
from sqlalchemy import select

FP_MAX = 0.01
MIN_COHORT = 100
MIN_COVERAGE = 0.5


def replay(rule, cohort_flats, flagged_flats):
    """Return (fp, cohort_n, hits, flagged_n): how the rule lands on each population.

    TODO (Round 3): count how many of cohort_flats (real customers) the rule
    matches, and how many of flagged_flats (the bots it should catch) it
    matches. defenses/rules.matches(rule, flat) does one match.
    """
    # Stub: pretend the rule hurts nobody and catches everything.
    return 0, len(cohort_flats), len(flagged_flats), len(flagged_flats)


def decide(rule, cohort_flats, flagged_flats):
    """Attach a gate result to the rule and return it.

    TODO (Round 3): reject when the cohort is too small (MIN_COHORT), when the
    false-positive rate exceeds FP_MAX, or when coverage is below
    MIN_COVERAGE. Otherwise pass. Record the numbers so approve.py and the
    scoreboard can show them.
    """
    fp, cohort_n, hits, flagged_n = replay(rule, cohort_flats, flagged_flats)
    res = {"decision": "pass", "reasons": [], "cohort_n": cohort_n, "fp": fp,
           "fp_rate": round(fp / cohort_n, 4) if cohort_n else 0.0,
           "flagged_n": flagged_n, "hits": hits,
           "coverage": round(hits / flagged_n, 3) if flagged_n else 0.0}
    rule["gate"] = res
    return res


def load_cohorts(conn, run_id="r3-train", tag="r3"):
    cohort = [flatten(card_for_sid(conn, sid)) for sid in verified_sids(conn)
              if card_for_sid(conn, sid)]
    rows = conn.execute(select(verdicts_t.c.sid).where(
        verdicts_t.c.run_id == run_id, verdicts_t.c.tag == tag, verdicts_t.c.label == "bot")).all()
    flagged = [flatten(card_for_sid(conn, sid)) for (sid,) in rows if card_for_sid(conn, sid)]
    return cohort, flagged


def run(run_id="r3-train", tag="r3"):
    if not os.path.exists(PENDING_FILE):
        print("no candidates: run defenses/rulesmith.py first")
        return 1
    with open(PENDING_FILE) as fh:
        doc = json.load(fh)
    with make_engine().connect() as conn:
        cohort, flagged = load_cohorts(conn, run_id, tag)
    passed = rejected = 0
    print(f"gate: cohort={len(cohort)} verified sessions, flagged pool={len(flagged)}\n")
    for rule in doc.get("rules", []):
        res = decide(rule, cohort, flagged)
        passed += res["decision"] == "pass"
        rejected += res["decision"] == "reject"
        conds = " AND ".join(f"{c['field']} {c['op']} {c['value']!r}"
                             for c in rule.get("when", {}).get("all", []))
        extra = f"fp {res.get('fp')}/{res.get('cohort_n')} cov {res.get('coverage', 0):.0%}"
        print(f"  [{res['decision'].upper():<6}] {conds[:66]:<66} {extra}")
    with open(PENDING_FILE, "w") as fh:
        json.dump(doc, fh, indent=2)
    print(f"\n{passed} pass, {rejected} reject.  (Stub passes everything — implement decide().)")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Replay candidate rules against real customers.")
    ap.add_argument("--run", default="r3-train")
    ap.add_argument("--tag", default="r3")
    args = ap.parse_args()
    return run(args.run, args.tag)


if __name__ == "__main__":
    sys.exit(main())
