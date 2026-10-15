"""
Watch the canary and roll back if it hurts people (Round 3)

A canary is only safe if something is watching it with a finger on the kill
switch. This scores the most recent week of logged sessions with the current
prod and canary models (offline, from the feature vectors in the log, the
same holdout replay a real watcher does against Prometheus series) and
compares them on the same real users:

    disagreement   share of sessions where canary and prod verdicts differ
    canary FP      share of real users the canary would act on but prod
                   would not: the divergence that hurts people

If canary FP exceeds prod\'s by more than ROLLBACK_FP_DIFF, it sets
canary_pct to 0 (defenses/config.py) and says so. Run it once, or --loop to
poll like the real daemon.

    python tools/rollback_watcher.py
    python tools/rollback_watcher.py --loop

It never promotes and never raises the percentage; a watcher\'s only
authority is to pull traffic off a model that is misbehaving.
"""

import argparse
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from report import by_week, decisions, is_bot, read_log  # noqa: E402  (puts the lab root on sys.path)
from defenses import config, registry  # noqa: E402
from defenses import mlfeatures as features  # noqa: E402
from defenses.model import verdict  # noqa: E402

ROLLBACK_FP_DIFF = 0.02


def _score(version, es):
    import lightgbm as lgb
    booster = lgb.Booster(model_file=registry.model_path(version))
    meta = registry.load()["versions"][version]
    X = np.array([features.from_log(e) for e in es], dtype=float)
    return [verdict(p, meta) != "clean" for p in booster.predict(X)]


def reading():
    prod, _ = registry.get("prod")
    canary, _ = registry.get("canary")
    if not prod or not canary:
        return None
    entries = decisions(read_log())
    week = max((e.get("week", 0) for e in entries), default=0)
    es = by_week(entries, week)
    if not es:
        return None
    pa, ca = _score(prod, es), _score(canary, es)
    disagree = sum(1 for i in range(len(es)) if pa[i] != ca[i]) / len(es)
    humans = [i for i in range(len(es)) if not is_bot(es[i])]
    canary_fp = sum(1 for i in humans if ca[i]) / len(humans) if humans else 0.0
    prod_fp = sum(1 for i in humans if pa[i]) / len(humans) if humans else 0.0
    return {"week": week, "n": len(es), "disagree": disagree,
            "canary_fp": canary_fp, "prod_fp": prod_fp, "diff": canary_fp - prod_fp}


def check():
    r = reading()
    if r is None:
        print("no prod+canary models set (tools/roles.py canary <version>)")
        return 0
    print(f"week {r['week']}: {r['n']} sessions, disagreement {100 * r['disagree']:.1f}%, "
          f"canary FP {100 * r['canary_fp']:.1f}% vs prod {100 * r['prod_fp']:.1f}% "
          f"(diff {100 * r['diff']:+.1f} pts)")
    if r["diff"] > ROLLBACK_FP_DIFF:
        config.update(canary_pct=0)
        print(f"🔴 ROLLBACK: canary FP diverged by {100 * r['diff']:.1f} pts > "
              f"{100 * ROLLBACK_FP_DIFF:.0f}. Set canary_pct to 0.")
        return 1
    print("🟢 canary within budget; no action")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()
    if not args.loop:
        return check()
    try:
        while True:
            if check():
                return 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
