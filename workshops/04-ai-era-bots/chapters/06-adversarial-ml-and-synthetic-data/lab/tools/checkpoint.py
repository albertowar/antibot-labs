"""
Round checkpoint for W4 Ch6 (Adversarial ML & Synthetic Data). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run this round's attackers next to 200 real customers
    python tools/checkpoint.py --round 3 --level 2    # the same attackers against Round 2's model (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 AND train the reference models
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N (level 0 is the bare store: the event log is written, nothing is scored).
Level L scores with model v(L+1); the oracle guard (Round 1) sits in front of it from level 1. Each round
runs the attackers that matter at that level, plus the earlier ones to prove they are still dead:

    round  attacker                         defense                        what you should see
    -----  -------------------------------  -----------------------------  -----------------------------------------
      0    baseline scalpers                none (log only); labels audited  all succeed · 0 wrong labels
      1    cheap and patient extractors     per-address oracle budget      cheap clone collapses · patient clone intact
      2    evasion from the clone           adversarial training, monotone evasion ~0
      3    (the poisoning wave retrains)    provenance sanitization        privacy-browser customers back under budget
      4    slow mobile reseller             SMOTE for the rare class       reseller ~0 at an honest cost

Next to the attackers, 200 real customers shop (tools/personas_ch6.py), in six cohorts. `hurt` is a
customer refused at the purchase; the budget per round is how many you accept losing. The defender cost is
the model check's own time per purchase (`ml_ms` in the decision log); the attacker cost is simulated proxy
and fingerprint spend per successful purchase.

Before the first round that scores, the checkpoint makes sure the drop-day history exists
(tools/simulate.py, about 2 minutes, once) and that the models for the level exist (tools/ml_setup.py).
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import ml_setup  # noqa: E402,F401  (wraps labclient.reset and checkpoint_core.catch_up)
import personas_ch6  # noqa: E402  (swaps in the drop-day cohort and the `drop_day` scenario)
from checkpoint_core import Round, main  # noqa: E402
import labclient  # noqa: E402
from shopper import DROP  # noqa: E402

ATTACKS = {
    "baseline": "attacks/round0_baseline.py --n 20",
    "cheap": "attacks/round1_extract.py",
    "patient": "attacks/round1_extract.py --patient",
    "evade": "attacks/round2_evade.py --n 40 --seed 131",
    "reseller": "attacks/round4_rareclass.py --n 40 --seed 141",
}
ML_MS_MEDIAN_MAX = 250.0        # defender cost: median time of the model check under a 16-thread flood (one purchase alone: a few ms)
PRIVACY_MAX = 0.15              # Round 3 and 4: the share of privacy-browser customers you accept refusing


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


def clones(cheap, patient):
    """Round 1: how much of the allowed region each extractor's surrogate recovered (of the 16 configs that really pass)."""
    def check(board, results, attacks):
        bad = []
        print("\nextractors                 fidelity   allowed region found   expected      attacker cost")
        for name, (lo, hi) in (("cheap", cheap), ("patient", patient)):
            out = attacks.get(name) or {}
            got = out.get("allowed_found")
            print(f"  {name:<22}{out.get('fidelity', 0):>8.0%}{'' if got is None else f'{got:>16.0%}'}{lo:>12.0%}-{hi:.0%}   ${out.get('usd', 0):.2f} for {out.get('queries', 0)} probes")
            if got is None or not lo <= got <= hi:
                bad.append(f"{name}: clone found {'nothing' if got is None else f'{got:.0%}'} of the allowed region, expected {lo:.0%}-{hi:.0%}")
        return (not bad, "; ".join(bad))
    return check


def people(board, results, attacks):
    """The false-positive accounting, per cohort (the budget itself is Round.humans_hurt_max)."""
    rows = personas_ch6.summarize(results)
    print("\nreal customers (cohort)    n  refused")
    for cohort, r in sorted(rows.items()):
        print(f"  {cohort:<22}{r['people']:>4}{r['hurt']:>8}   ({r['hurt'] / r['people']:.0%})")
    total = sum(r["people"] for r in rows.values())
    print(f"  total {sum(r['hurt'] for r in rows.values())}/{total}")
    return (True, "")


def privacy_share(board, results, attacks):
    """Rounds 3 and 4: the cohort the poisoning attack was aimed at."""
    row = personas_ch6.summarize(results).get("privacy_browser")
    if not row:
        return (True, "")
    share = row["hurt"] / row["people"]
    return (share <= PRIVACY_MAX, f"privacy_browser customers refused: {row['hurt']}/{row['people']} ({share:.0%}) > {PRIVACY_MAX:.0%}")


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
    1: make_round(1, "L1 baseline model v2 behind the oracle guard", ["baseline", "cheap", "patient"],
                  ("defenses/oracle_guard.py",),
                  [attackers(baseline=(0.0, 0.10)), clones(cheap=(0.0, 0.5), patient=(0.9, 1.0))], 6),
    2: make_round(2, "L2 model v3: adversarial training + monotone constraints", ["baseline", "evade"],
                  ("defenses/robust_train.py",),
                  [attackers(baseline=(0.0, 0.10), evade=(0.0, 0.20))], 10),
    3: make_round(3, "L3 model v4: provenance-sanitized training set", ["baseline", "evade"],
                  ("defenses/provenance.py",),
                  [attackers(baseline=(0.0, 0.10), evade=(0.0, 0.20)), privacy_share], 10),
    4: make_round(4, "L4 model v5: SMOTE for the rare class", ["baseline", "evade", "reseller"],
                  ("defenses/augment.py",),
                  [attackers(baseline=(0.0, 0.10), evade=(0.0, 0.20), reseller=(0.0, 0.25)), privacy_share], 12),
}

if __name__ == "__main__":
    main(ROUNDS)
