"""
Chapter 4 (W3), Round 1: Signal health

A sensor that stops firing throws no error. It just goes quiet, and the
score it used to feed drifts down with it. The only way to notice is to
know what "normal" looked like and compare. This module reads the decision
log (what Prometheus would hold as counters) and computes, per lab week:

    signal rate      share of logins on which each signal fired
    action rate      share of logins allowed / challenged / blocked
    cred rate        share of valid / wrong_password / unknown_user outcomes
    known-good rate  share of the known-good cohort each signal fired on

and raises alerts against the baseline week:

    silent       a signal fires at < SILENT_RATIO of its baseline rate.
                 Either the bots stopped showing it (burned) or the sensor
                 broke. Both need a person.
    surge        a signal fires at > SURGE_RATIO of baseline. New bot wave,
                 or a browser release made real users show it (Round 2).
    known_good   a signal fired on more than KNOWN_GOOD_FP_MAX of the cohort
                 that must never trip it. The one live false-positive rate
                 you have, measured on people who are not representative.
    blocks_down  the block rate fell below BLOCK_DROP of baseline. Either
                 fewer bots, or the same bots walking through.
    failures_up  wrong_password + unknown_user above FAILURE_SURGE of
                 baseline. Customers do not forget their passwords all at
                 once; a stuffing run does (Round 4).

What it cannot tell you: which of the two explanations is true. That takes
labels (Round 3) or an analyst. Health monitoring buys you the *question*
a day early, not the answer.
"""

from collections import Counter, defaultdict

BASELINE_WEEK = 1
MIN_BASELINE_RATE = 0.02   # a signal that never fired in the baseline cannot go silent

# TODO (Round 1): these ratios decide how early you hear about a burned
# signal and how often you are woken for nothing. Run `python tools/alerts.py
# --week 2`, then tighten or loosen them and run it again for week 1 (where
# nothing should fire).
SILENT_RATIO = 0.25
SURGE_RATIO = 3.0
KNOWN_GOOD_FP_MAX = 0.05
BLOCK_DROP = 0.5
FAILURE_SURGE = 2.0


def flat(entry):
    return [s for sigs in entry["signals"].values() for s in sigs]


def per_week(entries):
    weeks = defaultdict(list)
    for e in entries:
        weeks[e.get("week", 0)].append(e)
    stats = {}
    for week, es in sorted(weeks.items()):
        n = len(es)
        sig = Counter(s for e in es for s in set(flat(e)))
        act = Counter(e["action"] for e in es)
        cred = Counter(e["cred"] for e in es)
        kg = [e for e in es if e.get("known_good")]
        kg_sig = Counter(s for e in kg for s in set(flat(e)))
        stats[week] = {
            "n": n,
            "signal_rate": {s: c / n for s, c in sig.items()},
            "action_rate": {a: c / n for a, c in act.items()},
            "cred_rate": {c: v / n for c, v in cred.items()},
            "known_good_n": len(kg),
            "known_good_rate": {s: c / len(kg) for s, c in kg_sig.items()} if kg else {},
        }
    return stats


def alerts(stats, week, baseline_week=BASELINE_WEEK):
    """[(severity, rule, message)] for `week` against the baseline."""
    out = []
    cur, base = stats.get(week), stats.get(baseline_week)
    if not cur or not base:
        return out
    for s, b in sorted(base["signal_rate"].items()):
        c = cur["signal_rate"].get(s, 0.0)
        if b >= MIN_BASELINE_RATE and c < SILENT_RATIO * b:
            out.append(("warn", "silent", f"{s}: {100 * c:.1f}% of logins, baseline {100 * b:.1f}% "
                                          f"({100 * (c - b) / b:+.0f}%)"))
    for s, c in sorted(cur["signal_rate"].items()):
        b = base["signal_rate"].get(s, 0.0)
        if c >= 0.02 and c > SURGE_RATIO * max(b, 0.005):
            out.append(("warn", "surge", f"{s}: {100 * c:.1f}% of logins, baseline {100 * b:.1f}%"))
    for s, r in sorted(cur["known_good_rate"].items(), key=lambda kv: -kv[1]):
        if r > KNOWN_GOOD_FP_MAX:
            out.append(("crit", "known_good", f"{s} fired on {100 * r:.0f}% of the known-good cohort "
                                              f"(n={cur['known_good_n']})"))
    b_block, c_block = base["action_rate"].get("block", 0.0), cur["action_rate"].get("block", 0.0)
    if b_block >= 0.05 and c_block < BLOCK_DROP * b_block:
        out.append(("warn", "blocks_down", f"block rate {100 * c_block:.1f}%, baseline {100 * b_block:.1f}%"))
    fail = lambda st: st["cred_rate"].get("wrong_password", 0) + st["cred_rate"].get("unknown_user", 0)
    if fail(cur) > FAILURE_SURGE * max(fail(base), 0.02) and fail(cur) - fail(base) >= 0.05:
        out.append(("crit", "failures_up", f"failed logins {100 * fail(cur):.0f}% of attempts, "
                                           f"baseline {100 * fail(base):.0f}%"))
    return out
