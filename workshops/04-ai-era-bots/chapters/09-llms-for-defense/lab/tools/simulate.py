"""
W4 Ch9 — Drop-day traffic: simulated real users (+ the usual bots)

Generates the sessions the analyst triages and the real users every checkpoint
measures false positives on. The six human cohorts live in
tools/personas_llm.py; the baseline bots in attacks/round0_baseline.py.

Run (the store must be up: python demo_site/app.py):
    python tools/simulate.py                 # 600 real users + baseline bots
    python tools/simulate.py --no-bots       # real users only
    python tools/simulate.py --humans 200 --seed 7

The window is recorded as run `simulate-<seed>` (data/runs.json), so
`python -m defenses.triage --since-run simulate-1` finds exactly these sessions.
"""

import argparse
import time
from collections import Counter

import labclient  # noqa: F401  (the labnet guard runs on import)
import personas_llm as pl
import population
from defenses.sessionize import record_run


def main():
    ap = argparse.ArgumentParser(description="Generate drop-day traffic.")
    ap.add_argument("--humans", type=int, default=600)
    ap.add_argument("--no-bots", action="store_true")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    labclient.wait_for_store()
    run_name = f"simulate-{args.seed}"
    print(f"=== Drop day: {args.humans} real users"
          f"{'' if args.no_bots else ' + baseline bots'} → {labclient.BASE_URL} ===")
    t0 = time.time()
    results = population.run("llm_shop", people=pl.people(args.humans, args.seed),
                             seed=args.seed, threads=16, quiet=True)
    if not args.no_bots:
        import importlib.util
        import os
        spec = importlib.util.spec_from_file_location(
            "round0_baseline", os.path.join(os.path.dirname(__file__), "..", "attacks", "round0_baseline.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        bots = mod.run(seed=args.seed + 500)
        print(f"  + {len(bots)} baseline bot sessions")
    record_run(run_name, t0, time.time())
    by = Counter((r["persona"], r.get("outcome")) for r in results)
    for (cohort, outcome), n in sorted(by.items(), key=str):
        print(f"  human {cohort:<16} {str(outcome):<10} {n}")
    print(f"\n{len(results)} human sessions; window recorded as run={run_name}.")


if __name__ == "__main__":
    main()
