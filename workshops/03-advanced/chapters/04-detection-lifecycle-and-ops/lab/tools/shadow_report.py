"""
Does the shadow model deserve to act? (Round 3)

A model in the shadow role is validated the only safe way: by scoring real
traffic it never acted on. This scores a week of logged sessions with the
current prod and shadow models (offline, from the feature vectors in the
log, exactly as you would replay a holdout), so it works whether or not the
shadow model was live when that traffic arrived.

    python tools/shadow_report.py
    python tools/shadow_report.py --week 4

It prints the agreement matrix (prod verdict x shadow verdict) and, using the
lab\'s ground truth, what each model would do to bots and to real users. The
number to watch is "real users the shadow would newly act on": a shadow that
catches more bots is only worth promoting if that column stays near zero.
"""

import argparse
import os
import sys
from collections import Counter

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from report import by_week, decisions, is_bot, read_log  # noqa: E402  (puts the lab root on sys.path)
from defenses import mlfeatures as features  # noqa: E402
from defenses import registry  # noqa: E402
from defenses.model import verdict  # noqa: E402


def score(version, entries):
    import lightgbm as lgb
    booster = lgb.Booster(model_file=registry.model_path(version))
    meta = registry.load()["versions"][version]
    X = np.array([features.from_log(e) for e in entries], dtype=float)
    return [verdict(p, meta) for p in booster.predict(X)]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--week", type=int)
    args = parser.parse_args()
    prod, _ = registry.get("prod")
    shadow, _ = registry.get("shadow")
    if not prod or not shadow:
        print("need both a prod and a shadow model (tools/roles.py shadow <version>)")
        return 1
    entries = decisions(read_log())
    week = args.week or max((e.get("week", 0) for e in entries), default=0)
    es = by_week(entries, week)
    if not es:
        print(f"no sessions logged for week {week}")
        return 1
    pv, sv = score(prod, es), score(shadow, es)
    print(f"=== shadow report, week {week}: prod {prod} vs shadow {shadow} "
          f"({len(es)} sessions) ===\n")

    verdicts = ["clean", "suspicious", "bot"]
    matrix = Counter(zip(pv, sv))
    header = "prod \\ shadow"
    print("  " + header.ljust(16) + "".join(f"{v:>12}" for v in verdicts))
    for p in verdicts:
        print("  " + p.ljust(16) + "".join(f"{matrix.get((p, s), 0):>12}" for s in verdicts))
    disagree = sum(v for (p, s), v in matrix.items() if p != s)
    print(f"  disagreement: {disagree}/{len(es)} ({100 * disagree / len(es):.1f}%)\n")

    acts_p = [v != "clean" for v in pv]
    acts_s = [v != "clean" for v in sv]
    bot = [is_bot(e) for e in es]
    newly_users = sum(1 for i in range(len(es)) if acts_s[i] and not acts_p[i] and not bot[i])
    newly_bots = sum(1 for i in range(len(es)) if acts_s[i] and not acts_p[i] and bot[i])
    nb, nh = sum(bot), sum(1 for b in bot if not b)
    print(f"  bots the shadow would newly act on:        {newly_bots} / {nb}")
    print(f"  real users the shadow would newly act on:  {newly_users} / {nh}  "
          f"<- this must stay near zero")
    if newly_users:
        who = Counter(es[i]["actor"].split(":")[1] for i in range(len(es))
                      if acts_s[i] and not acts_p[i] and not bot[i])
        print("    " + ", ".join(f"{p} {n}" for p, n in who.most_common()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
