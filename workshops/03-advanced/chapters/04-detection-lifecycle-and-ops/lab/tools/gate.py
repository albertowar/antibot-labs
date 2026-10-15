"""
Chapter 4 (W3): The promotion gate

    python tools/gate.py --candidate v2            judge v2 against the current prod model
    python tools/gate.py --candidate v2 --week 4   on week 4's traffic only

A candidate may replace production only if it is *not worse where it
matters*, measured on traffic the candidate did not train on in the way it
will be used. Three evidence sets, all taken from the decision log:

    weak        last week's weak-labelled sessions. Cheap, large, and
                circular: a bot the current model let in is labelled human.
    analyst     every session a person labelled (data/labels.jsonl). Small,
                expensive, the only set that can contradict production.
    known-good  the monitors and QA accounts. Not a bot in sight, so it
                measures one thing: how often the model fires on people it
                must never fire on.

Rules (REQUIRE_ANALYST and the budgets are the operator's decision):
    recall on bots   candidate >= prod - RECALL_SLACK      on every set used
    FP on humans     candidate's rate at t_bot <= FP_BUDGET on weak humans and on known-good
    analyst set      required when REQUIRE_ANALYST, else used if present

The gate prints a table and says PASS or REFUSE. It never promotes. That
is tools/roles.py's job, with a human on the keyboard.
"""

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import labels  # noqa: E402
from report import decisions, read_log  # noqa: E402  (puts the lab root on sys.path)
from defenses import mlfeatures as features  # noqa: E402
from defenses import registry  # noqa: E402
from defenses.model import verdict  # noqa: E402

# TODO (Round 3): the naive gate (REQUIRE_ANALYST = False) judges on weak
# labels alone, and so it waves through a model that is blind to the week-4
# evader, because the weak labels call that evader human. Turn REQUIRE_ANALYST
# on once you have seen that happen: now a candidate must prove itself on a
# set a person actually looked at, and clear MIN_ANALYST_RECALL on it.
REQUIRE_ANALYST = True
RECALL_SLACK = 0.02
FP_BUDGET = 0.01
MIN_ANALYST_RECALL = 0.5


def scores(version, X):
    import lightgbm as lgb
    booster = lgb.Booster(model_file=registry.model_path(version))
    meta = registry.load()["versions"][version]
    p = booster.predict(X) if len(X) else np.array([])
    return np.array([verdict(x, meta) for x in p]), p


def evaluate(version, rows):
    if not rows:
        return None
    X = np.array([features.from_log(e) for e, _ in rows], dtype=float)
    y = np.array([l == "bot" for _, l in rows])
    v, _ = scores(version, X)
    fires = (v == "bot")
    return {"n": len(rows), "bots": int(y.sum()),
            "recall": float(fires[y].mean()) if y.any() else None,
            "fp": float(fires[~y].mean()) if (~y).any() else None,
            "challenge_fp": float(((v != "clean") & ~y).sum() / max(1, (~y).sum()))}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--week", type=int, help="evaluate on this week only (default: last week in the log)")
    args = parser.parse_args()

    prod, _ = registry.get("prod")
    entries = decisions(read_log())
    week = args.week or max((e.get("week", 0) for e in entries), default=0)
    recent = [e for e in entries if e.get("week") == week]
    sets = {
        "weak (week %d)" % week: labels.labelled(recent, "weak"),
        "analyst": labels.labelled(entries, "analyst"),
        "known-good": [(e, "human") for e in entries if e.get("known_good")],
    }
    print(f"gate: candidate {args.candidate} vs prod {prod or '(none)'}\n")
    print(f"{'evidence set':<18} {'n':>5} {'bots':>5} {'model':<6} {'recall':>7} {'fp@bot':>7} {'fp@sus':>7}")
    verdicts, reasons = [], []
    for name, rows in sets.items():
        if not rows or (name == "analyst" and not any(l == "bot" for _, l in rows)):
            print(f"{name:<18} {'-':>5}  (no {'labelled bots' if rows else 'sessions'})")
            if name == "analyst" and REQUIRE_ANALYST:
                reasons.append("no analyst-confirmed bot sessions to judge on; a weak-label-only "
                               "gate is circular. Label a sample first (tools/label.py).")
            continue
        results = {}
        for version in [v for v in (prod, args.candidate) if v]:
            r = evaluate(version, rows)
            results[version] = r
            fmt = lambda x: "   -   " if x is None else f"{100 * x:6.1f}%"
            print(f"{name:<18} {r['n']:>5} {r['bots']:>5} {version:<6} {fmt(r['recall'])} {fmt(r['fp'])} {fmt(r['challenge_fp'])}")
        c = results[args.candidate]
        # Weak labels are shown for context but never gate a decision: they
        # are the circular signal this whole chapter is about. Rules apply
        # only to the analyst-labelled and known-good sets.
        if name.startswith("weak"):
            continue
        if prod and results[prod]["recall"] is not None and c["recall"] is not None \
                and c["recall"] < results[prod]["recall"] - RECALL_SLACK:
            reasons.append(f"{name}: recall {100 * c['recall']:.1f}% is below prod's "
                           f"{100 * results[prod]['recall']:.1f}% by more than {100 * RECALL_SLACK:.0f} pts")
        if c["fp"] is not None and c["fp"] > FP_BUDGET:
            reasons.append(f"{name}: acts on {100 * c['fp']:.1f}% of real users, budget {100 * FP_BUDGET:.0f}%")
        if name == "analyst" and c["recall"] is not None and c["recall"] < MIN_ANALYST_RECALL:
            reasons.append(f"analyst set: catches only {100 * c['recall']:.0f}% of confirmed bots, "
                           f"floor {100 * MIN_ANALYST_RECALL:.0f}% (it is blind to this attack)")
    print()
    if reasons:
        for r in reasons:
            print(f"❌ REFUSE: {r}")
        return 1
    print(f"✅ PASS: {args.candidate} may replace {prod or 'nothing'}. "
          f"Shadow or canary it first: tools/roles.py shadow {args.candidate}")
    if not sets["analyst"]:
        print("   (judged on weak labels and the known-good cohort only; nobody has looked at a session)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
