"""
W4 Chapter 7 — The gate: replay every candidate rule before it can block anyone

A drafted rule is a claim. The gate tests it against the two populations
that matter:

  legit cohort   sessions that logged into a long-standing account
                 (sessionize.verified_sids). This is NOT ground truth — it is
                 what production actually has, the customers you already
                 trust. A rule that blocks them is rejected, full stop.
  flagged pool   the bot-labelled sessions the rule is meant to catch, so we
                 know it does something (coverage).

Decision (defenses/gate.decide):
  reject if the cohort is too small to measure (MIN_COHORT),
  reject if it blocks more than FP_MAX of the cohort,
  reject if it covers less than MIN_COVERAGE of its flagged pool,
  otherwise pass.

The cohort bias is the lesson, not a bug: VPN and privacy-browser users log
in less, so they are under-represented here. A rule that mostly hurts them
can still slip through with a low measured FP. The gate shrinks the risk; it
does not erase it. With a 0-of-N clean replay the true rate could still be
about 3/N at the 95% bound — evidence, not proof. The scoreboard prints an
oracle comparison (against truth) so you can see where the gate was blind.
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
    """Return (fp, cohort_n, hits, flagged_n): how the rule lands on each population."""
    fp = sum(1 for f in cohort_flats if matches(rule, f))
    hits = sum(1 for f in flagged_flats if matches(rule, f))
    return fp, len(cohort_flats), hits, len(flagged_flats)


def decide(rule, cohort_flats, flagged_flats):
    """Attach a gate result to the rule. Returns the result dict."""
    try:
        check_rule(rule)
    except ValueError as e:
        res = {"decision": "reject", "reasons": ["invalid"], "detail": str(e)}
        rule["gate"] = res
        return res
    fp, cohort_n, hits, flagged_n = replay(rule, cohort_flats, flagged_flats)
    fp_rate = fp / cohort_n if cohort_n else 1.0
    coverage = hits / flagged_n if flagged_n else 0.0
    reasons = []
    if cohort_n < MIN_COHORT:
        reasons.append("insufficient_cohort")
    if fp_rate > FP_MAX:
        reasons.append("fp_rate")
    if coverage < MIN_COVERAGE:
        reasons.append("no_coverage")
    res = {"decision": "reject" if reasons else "pass", "reasons": reasons,
           "cohort_n": cohort_n, "fp": fp, "fp_rate": round(fp_rate, 4),
           "flagged_n": flagged_n, "hits": hits, "coverage": round(coverage, 3)}
    rule["gate"] = res
    return res


def load_cohorts(conn, run_id="r3-train", tag="r3"):
    """Build the legit cohort and the flagged pool as lists of flat cards."""
    cohort = []
    for sid in verified_sids(conn):
        card = card_for_sid(conn, sid)
        if card:
            cohort.append(flatten(card))
    rows = conn.execute(select(verdicts_t.c.sid).where(
        verdicts_t.c.run_id == run_id, verdicts_t.c.tag == tag, verdicts_t.c.label == "bot")).all()
    flagged = []
    for (sid,) in rows:
        card = card_for_sid(conn, sid)
        if card:
            flagged.append(flatten(card))
    return cohort, flagged


def run(run_id="r3-train", tag="r3"):
    if not os.path.exists(PENDING_FILE):
        print(f"no candidates: run defenses/rulesmith.py first")
        return 1
    with open(PENDING_FILE) as fh:
        doc = json.load(fh)
    with make_engine().connect() as conn:
        cohort, flagged = load_cohorts(conn, run_id, tag)
    passed = rejected = 0
    print(f"gate: cohort={len(cohort)} verified sessions, flagged pool={len(flagged)} "
          f"(FP_MAX={FP_MAX:.0%}, MIN_COHORT={MIN_COHORT}, MIN_COVERAGE={MIN_COVERAGE:.0%})\n")
    for rule in doc.get("rules", []):
        res = decide(rule, cohort, flagged)
        passed += res["decision"] == "pass"
        rejected += res["decision"] == "reject"
        conds = " AND ".join(f"{c['field']} {c['op']} {c['value']!r}" for c in rule["when"]["all"]) \
            if "when" in rule else "(invalid)"
        tag_s = "PASS " if res["decision"] == "pass" else "REJECT"
        extra = (f"fp {res.get('fp')}/{res.get('cohort_n')} ({res.get('fp_rate', 0):.1%}) "
                 f"cov {res.get('coverage', 0):.0%}" if "fp" in res else res.get("detail", ""))
        why = "" if res["decision"] == "pass" else "  <- " + ",".join(res["reasons"])
        print(f"  [{tag_s}] {conds[:70]:<70} {extra}{why}")
    with open(PENDING_FILE, "w") as fh:
        json.dump(doc, fh, indent=2)
    print(f"\n{passed} pass, {rejected} reject. "
          f"Approve the keepers: python tools/approve.py --list")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Replay candidate rules against real customers.")
    ap.add_argument("--run", default="r3-train")
    ap.add_argument("--tag", default="r3")
    args = ap.parse_args()
    return run(args.run, args.tag)


if __name__ == "__main__":
    sys.exit(main())
