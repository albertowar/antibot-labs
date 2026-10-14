"""
Round checkpoint for W2 Ch7 (Machine Learning for Bot Detection). Declares the rounds and hands over
to checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run this round's attackers next to 200 real customers
    python tools/checkpoint.py --round 3 --level 2    # the same attackers against Round 2's defense (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 AND train the reference models
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N (level 0 is the bare store: the event log is written, nothing is scored).
Each round runs the attackers that matter at that level, plus the earlier ones to prove they are still
dead:

    round  defense added                              attackers run                          what you should see
    -----  -----------------------------------------  -------------------------------------  --------------------------------
      0    none (log only); weak labels audited       baseline scalpers                      all succeed · 0 wrong labels
      1    model v1, per-session features             baseline, humanized                    baseline ~0 · humanized all through
      2    model v2: cohort features + cluster labels baseline, humanized, farm              humanized ~0 · farm all through
      3    + device-claim anomaly detector            baseline, humanized, farm, prober      farm ~0 · prober gets through
      4    deferred, uniform enforcement              ... prober, patient prober             prober ~0 · patient prober wins

Next to the attackers, 200 real customers shop (tools/personas_ch7.py), in six cohorts. `hurt` is a
customer blocked at the purchase or cancelled at review; the budget per round is the share of them
you accept losing. The defender cost is the model check's own time per purchase (`ml_ms` in the
decision log); the attacker cost is simulated proxy and fingerprint spend per successful purchase.

Before the first round that scores, the checkpoint makes sure the drop-day history exists
(tools/simulate.py, about 2 minutes, once) and that the models for the level exist (tools/ml_setup.py).
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import ml_setup  # noqa: E402,F401  (wraps labclient.reset and checkpoint_core.catch_up)
import personas_ch7  # noqa: E402  (swaps in the drop-day cohort and the `drop_day` scenario)
from checkpoint_core import Round, main  # noqa: E402
import labclient  # noqa: E402
from shopper import DROP  # noqa: E402

ATTACKS = {
    "baseline": "attacks/round0_baseline.py --n 20",
    "humanized": "attacks/round1_humanized.py --n 30 --seed 121",
    "farm": "attacks/round2_farm.py --n 30 --seed 131",
    "prober": "attacks/round3_oracle_prober.py --seed 141",
    "patient": "attacks/round3_oracle_prober.py --patient --seed 151",
}
ML_MS_MEDIAN_MAX = 250.0        # defender cost: median time of the model check under a 16-thread flood (one purchase alone: a few ms)


def rate(attacks, name):
    out = attacks.get(name) or {}
    return out.get("succeeded", 0) / out["attempted"] if out.get("attempted") else None


def attackers(**want):
    """want: name -> (lo, hi) share of purchases that succeeded. Prints the lines the README table is made of."""
    def check(board, results, attacks):
        bad = []
        print("\nattackers                  purchases   succeeded   expected      attacker cost")
        for name, (lo, hi) in want.items():
            got = rate(attacks, name)
            out = attacks.get(name) or {}
            n, k = out.get("attempted", 0), out.get("succeeded", 0)
            per = f"${out.get('usd', 0) / k:.2f} per success" if k else "no successful purchase"
            print(f"  {name:<22}{n:>6}{k:>11}  {'' if got is None else f'{got:>6.0%}'}   {lo:.0%}-{hi:.0%}   {per}")
            if got is None or not lo <= got <= hi:
                bad.append(f"{name}: {'no result' if got is None else f'{got:.0%}'} of purchases succeeded, expected {lo:.0%}-{hi:.0%}")
        return (not bad, "; ".join(bad))
    return check


def people(board, results, attacks):
    """The false-positive accounting, per cohort (the budget itself is Round.humans_hurt_max)."""
    rows = personas_ch7.summarize(results)
    print("\nreal customers (cohort)    n  blocked or cancelled")
    for cohort, r in sorted(rows.items()):
        print(f"  {cohort:<22}{r['people']:>4}{r['hurt']:>10}   ({r['hurt'] / r['people']:.0%})")
    total = sum(r["people"] for r in rows.values())
    print(f"  total {sum(r['hurt'] for r in rows.values())}/{total}")
    return (True, "")


def defender_cost(board, results, attacks):
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "path": f"/drop/{DROP}"})["items"]
    ms = [d["extra"]["ml_ms"] for d in rows if d["method"] == "POST" and "ml_ms" in d.get("extra", {})]
    if not ms:
        return (True, "")                                    # level 0: nothing is scored
    median = statistics.median(ms)
    p95 = statistics.quantiles(ms, n=20)[-1] if len(ms) > 1 else ms[0]
    print(f"\ndefender cost (the model check, while the attackers run)\n  ml check per purchase: median {median:.1f} ms, p95 {p95:.1f} ms over {len(ms)} purchases")
    return (median < ML_MS_MEDIAN_MAX, f"model check median {median:.1f} ms > {ML_MS_MEDIAN_MAX} ms")


def labels_audited(board, results, attacks):
    """Round 0: the weak labels are never wrong, and they cover only part of the bots (the bias to discuss)."""
    import audit
    a = audit.audit_labels()
    ok = a["wrong"] == 0 and 0.2 <= a["bot_coverage"] <= 0.85
    return (ok, f"weak labels: {a['wrong']} wrong, {a['bot_coverage']:.0%} of bots covered (want 0 wrong, 20%-85%)")


def make_round(level, description, attacks, solutions, checks, budget):
    return Round(level=level, description=description, scenario="drop_day",
                 attacks={name: ATTACKS[name] for name in attacks}, humans_hurt_max=budget,
                 extra_checks=[*checks, people, defender_cost], solutions=solutions)


ROUNDS = {
    0: make_round(0, "log only: the bare store, labels audited", ["baseline"], (),
                  [attackers(baseline=(0.9, 1.0)), labels_audited], 0),
    1: make_round(1, "L1 model v1, per-session features", ["baseline", "humanized"],
                  ("defenses/ladder.py", "defenses/ml_check.py"),
                  [attackers(baseline=(0.0, 0.10), humanized=(0.9, 1.0))], 6),
    2: make_round(2, "L2 model v2, cohort features + cluster labels", ["baseline", "humanized", "farm"],
                  ("defenses/cohort.py",),
                  [attackers(baseline=(0.0, 0.10), humanized=(0.0, 0.20), farm=(0.6, 1.0))], 10),
    3: make_round(3, "L3 + device-claim anomaly detector", ["baseline", "humanized", "farm", "prober"],
                  ("defenses/anomaly.py",),
                  [attackers(baseline=(0.0, 0.10), humanized=(0.0, 0.20), farm=(0.0, 0.15), prober=(0.6, 1.0))], 10),
    4: make_round(4, "L4 deferred, uniform enforcement", ["baseline", "farm", "prober", "patient"],
                  ("defenses/enforcement.py",),
                  [attackers(baseline=(0.0, 0.10), farm=(0.0, 0.15), prober=(0.0, 0.10), patient=(0.6, 1.0))], 10),
}

if __name__ == "__main__":
    main(ROUNDS)
