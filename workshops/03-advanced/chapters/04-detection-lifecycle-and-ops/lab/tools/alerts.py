"""
What Alertmanager would page you about

    python tools/alerts.py                 evaluate the latest week against the baseline
    python tools/alerts.py --week 2        a specific week
    python tools/alerts.py --baseline 1    change the reference week (default: week 1)
    python tools/alerts.py --drift         add the drift report (PSI / KS per feature)

Signal-health alerts come from tools/health.py, drift from tools/drift.py.
This tool is the glue a real deployment keeps in Prometheus alerting rules and
an Evidently test suite; here it runs the same checks against the decision log
so the lab needs no Docker to show the alert that would have fired.

Exit code is the number of critical alerts, so it can gate a script.
"""

import argparse
import sys

import drift  # noqa: E402
import health  # noqa: E402
from report import decisions, read_log  # noqa: E402

ICON = {"crit": "🔴", "warn": "🟠"}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--week", type=int)
    parser.add_argument("--baseline", type=int, default=health.BASELINE_WEEK)
    parser.add_argument("--drift", action="store_true")
    args = parser.parse_args()

    entries = decisions(read_log())
    if not entries:
        print("No decisions logged yet. Replay a week: python tools/weeks.py --week 1")
        return 1
    week = args.week or max(e.get("week", 0) for e in entries)
    stats = health.per_week(entries)

    print(f"=== alerts: week {week} vs baseline week {args.baseline} ===\n")
    alerts = health.alerts(stats, week, args.baseline)
    crit = 0
    if not alerts:
        print("  no health alerts (every signal within band)")
    for severity, rule, message in alerts:
        crit += severity == "crit"
        print(f"  {ICON[severity]} [{rule}] {message}")

    if args.drift:
        print(f"\n=== drift: week {week} vs week {args.baseline} ===")
        print(f"  {'feature':<26} {'PSI':>7} {'KS D':>6} {'KS p':>8}  status")
        for row in drift.report(entries, args.baseline, week):
            if row["psi"] < drift.PSI_WARN and row["ks_p"] > drift.KS_P and not row["status"]:
                continue
            print(f"  {row['feature']:<26} {row['psi']:>7.3f} {row['ks_d']:>6.2f} "
                  f"{row['ks_p']:>8.4f}  {row['status']}")
        ages = drift.corpus_ages(week)
        stale = {c: a for c, a in ages.items() if a > drift.CORPUS_MAX_AGE_WEEKS}
        print("  corpus age (weeks): " + ", ".join(f"{c} {a}" for c, a in ages.items())
              + (f"   🔴 stale: {', '.join(stale)}" if stale else ""))
        crit += len(stale)

    print()
    return crit


if __name__ == "__main__":
    sys.exit(main())
