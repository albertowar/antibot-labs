"""
Round checkpoint for W3 Ch9 (Fair Drops: Raffles & Risk-Scored Allocation). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, open the drop, run the crews next to the 110 fans
    python tools/checkpoint.py --round 3 --level 2    # the same crews against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N and each level includes the ones below it. Level 0 is Round 0: the drop is sold
first come, first served behind Chapter 4's funnel. From level 1 the store raffles it.

    round  defense added                                  crews run                   what you should see
    -----  ---------------------------------------------  --------------------------  ---------------------------
      0    first come, first served + Chapter 4's funnel  patient_farm                 the crew buys the drop out
      1    raffle: guests out, one entry per account      account_farm                 its share of units ~ its share of tickets
      2    verified email + trust-weighted tickets        account_farm, aged_farm      the fresh farm shrinks; bought accounts do not
      3    entity resolution: one entry per cluster       aged_farm, jig_farm          crews collapse; 12 real people go with them
      4    evidence graph + claim holds + re-score        jig_farm, spread_farm, crowd the jig crew merges, the spread crew is cancelled; the crowd keeps its odds

A round is one event, start to finish (tools/personas_ch9.py has the fans):

    reset -> open the event -> [fans and crews ENTER] -> draw -> [winners CLAIM] -> expire -> [promoted CLAIM]
          -> re-score -> [promoted CLAIM] -> re-score -> report

The fans run next to the crews' entries; the draw, the claim waves, the expiry and the re-scores are driven here,
after the entries, so every round is the same sequence whatever the defenses decide (a first-come round has no draw).
The fairness numbers are read from GET /lab/raffle/report, which joins entries to the decision log's ground truth.
"""

import json
import os
import statistics
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch9  # noqa: E402  (registers the ch9_* scenarios)
import population  # noqa: E402
import checkpoint_core  # noqa: E402
from checkpoint_core import Round, main  # noqa: E402
import labclient  # noqa: E402

OPEN_DELAY_S = 14.0                 # a first-come drop opens this long after the event is opened (staging time)
BATCH_MAX_MS = 2000.0               # defender cost: one draw or re-score over the whole entry list
UNITS = 50
FANS = 110
SKU = "lab-runner-9"

ATTACKS = {
    "patient_farm": ("attacks/round0_patient_farm.py", None),
    "account_farm": ("attacks/round1_account_farm.py", "account_farm"),
    "aged_farm": ("attacks/round2_aged_farm.py", "aged_farm"),
    "jig_farm": ("attacks/round3_jig_farm.py", "jig_farm"),
    "spread_farm": ("attacks/round3_jig_farm.py --spread", "spread_farm"),
    "crowd": ("attacks/round4_crowd_entrants.py", "crowd"),
}
STATE = {"people": [], "runs": {}, "report": None, "threads": 160}


# --- the event ---------------------------------------------------------------------------------------------

def setup(level, caught_up, delay=OPEN_DELAY_S):
    STATE.update(people=[], runs={}, report=None)
    labclient.admin("POST", "/lab/raffle/open", json={"delay_s": delay})


def fans():
    STATE["people"] = personas_ch9.people()
    return STATE["people"]


def crew_run(name):
    script, _ = ATTACKS[name]

    def go():
        out = checkpoint_core.run_attack(script)
        STATE["runs"][name] = out
        return out
    return go


def _claim_wave():
    """Everyone who was told they won pays. The lab plays the "you won" mail: the winners are read from the report,
    and each crew is handed the emails of its own accounts that won (its inboxes), nothing else."""
    won = [e for e in labclient.admin("GET", "/lab/raffle/report", params={"detail": 1})["entries"] if e["status"] == "won"]
    emails = {e["email"] for e in won}
    mine = [p for p in STATE["people"] if p.acct.email in emails]
    if mine:
        population.run(personas_ch9.scenario_claim, people=mine, seed=population.SEED, threads=64, quiet=True)
    for name, (script, cohort) in ATTACKS.items():
        wins = sorted(e["email"] for e in won if e["cohort"] == cohort) if cohort else []
        if name in STATE["runs"] and wins:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
                json.dump(wins, fh)
            try:
                checkpoint_core.run_attack(f"{script} --claim --wins {fh.name}")
            finally:
                os.unlink(fh.name)


def teardown(level):
    """The rest of the event, after the entries: draw, claim waves, expiry, re-scores, then read the report."""
    if level >= 1:
        admin = labclient.admin
        admin("POST", "/lab/raffle/draw")
        _claim_wave()
        promoted = admin("POST", "/lab/raffle/expire")["promoted"]
        if promoted:
            _claim_wave()
        for _ in range(2):                                   # the second re-score sees the claims the first one promoted
            promoted = admin("POST", "/lab/raffle/rescore")["promoted"]
            if promoted:
                _claim_wave()
    report = labclient.admin("GET", "/lab/raffle/report", params={"detail": 1})
    STATE["report"] = report
    _finalize(report, level)


def _finalize(report, level):
    """Turn the store's final state into each fan's outcome and each crew's units (ground truth, from the report)."""
    by_email = {e["email"]: e for e in report["entries"] or []}
    for p in STATE["people"]:
        e = by_email.get(p.acct.email)
        if e is None:
            continue                                         # first come: the scenario already set bought / sold_out
        st, reasons = e["status"], " ".join(e["reasons"])
        if st == "claimed":
            outcome = "bought"
        elif st == "held":
            outcome = "held"
        elif st == "excluded":
            outcome = "over_merged" if "cluster" in reasons else "excluded"
        elif st in ("expired", "cancelled"):
            outcome = "claim_blocked"
        else:
            outcome = "lost"
        p.result["outcome"] = outcome
    for name, (script, cohort) in ATTACKS.items():
        if level >= 1 and name in STATE["runs"] and cohort:
            STATE["runs"][name]["succeeded"] = report["cohorts"].get(cohort, {}).get("claimed", 0)


# --- the checks ----------------------------------------------------------------------------------------------

def attackers(**want):
    """want: name -> (lo, hi) on the units the crew finally holds."""
    def check(board, results, attacks):
        bad = []
        print("\ncrews                      units  expected")
        for name, (lo, hi) in want.items():
            got = (attacks.get(name) or {}).get("succeeded", -1)
            print(f"  {name:<22}{got:>5}   {lo}-{hi}")
            if not lo <= got <= hi:
                bad.append(f"{name}: got {got}, expected {lo}-{hi}")
        return (not bad, "; ".join(bad))
    return check


def fairness(fan_share=(0.0, 1.0), fan_odds=(0.0, 99.0), per_identity=(0.0, 99.0), held_max=999):
    """The numbers a raffle is judged on (from the report): share of the units that reached fans, tickets per
    identity, and a fan's win odds against a fair lottery (ideal 1.0)."""
    def check(board, results, attacks):
        m = STATE["report"]["metrics"]
        print(f"\nfairness (units {m['units']})\n  fans hold {m['fan_units']} pairs ({m['fan_share']:.0%}) · crews hold {m['bot_units']} "
              f"({m['bot_share']:.0%}) · held orders {m['held_orders']}\n  entries per identity {m['entries_per_identity']} "
              f"({m['entries']} entries, {m['identities']} identities) · fan odds vs a fair lottery {m['fan_odds_vs_fair']}")
        print("  cohort            kind  people  entries  merged  excluded  paid  held  cancelled  expired")
        for name, c in sorted(STATE["report"]["cohorts"].items(), key=lambda kv: (kv[1]["kind"], kv[0])):
            print(f"  {name:<16}{c['kind']:>6}{c['identities']:>8}{c['entries']:>9}{c['merged']:>8}{c['excluded']:>10}{c['claimed']:>6}"
                  f"{c['held']:>6}{c['cancelled']:>11}{c['expired']:>9}")
        bad = []
        for label, val, (lo, hi) in (("fan share", m["fan_share"], fan_share), ("fan odds vs fair", m["fan_odds_vs_fair"], fan_odds),
                                    ("entries per identity", m["entries_per_identity"], per_identity)):
            if val is not None and not lo <= val <= hi:
                bad.append(f"{label} {val}, expected {lo}-{hi}")
        if m["held_orders"] > held_max:
            bad.append(f"{m['held_orders']} orders left in review, at most {held_max}")
        return (not bad, "; ".join(bad))
    return check


def people(hurt=None, stepped_up=(0, 99), held_at_claim=(0, 0)):
    """The false-positive accounting by cohort. hurt: cohort -> (lo, hi) on how many of its people ended hurt
    (excluded, merged away, or a win that never became a pair); every other cohort must have none."""
    hurt = hurt or {}

    def check(board, results, attacks):
        rows = personas_ch9.summarize(results)
        n_hurt = sum(r["hurt"] for r in rows.values())
        n_step = sum(r["stepped_up"] for r in rows.values())
        per = ", ".join(f"{k} {v['hurt']}" for k, v in sorted(rows.items()) if v["hurt"]) or "none"
        step = ", ".join(f"{k} {v['stepped_up']}" for k, v in sorted(rows.items()) if v["stepped_up"]) or "none"
        held = sum(1 for r in results if r.get("claim_status") == 202)
        print(f"\nthe fans: {len(results)} people · hurt {n_hurt} ({per}) · stepped up {n_step} ({step}) · held for review at the claim {held}")
        bad = []
        for cohort, row in rows.items():
            lo, hi = hurt.get(cohort, (0, 0))
            if not lo <= row["hurt"] <= hi:
                bad.append(f"{cohort}: {row['hurt']} hurt, expected {lo}-{hi}")
        if not stepped_up[0] <= n_step <= stepped_up[1]:
            bad.append(f"{n_step} fans stepped up, expected {stepped_up[0]}-{stepped_up[1]}")
        if not held_at_claim[0] <= held <= held_at_claim[1]:
            bad.append(f"{held} fans held for review at the claim, expected {held_at_claim[0]}-{held_at_claim[1]}")
        return (not bad, "; ".join(bad))
    return check


def gate_cost(board, results, attacks):
    """Defender cost. Per request it is the fans' gate time from the decision log (printed, not judged: the harness
    runs the store and 170 client threads in one process, so a request waits its turn and the median measures the
    queue); the number the round judges is the BATCH phases, the cost a raffle adds: one draw over the whole list."""
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "actor": "human:"})["items"]
    ms = [d["ms"] for d in rows]
    if not ms:
        return (False, "no fan requests in the decision log")
    p95 = statistics.quantiles(ms, n=20)[-1] if len(ms) > 1 else ms[0]
    batch = [d for d in labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "actor": "you"})["items"]
             if d["phase"].startswith("raffle:")]
    print(f"defender cost\n  gate per fan request: median {statistics.median(ms):.1f} ms, p95 {p95:.1f} ms over {len(ms)} requests "
          f"(includes queueing behind {STATE['threads']} client threads)"
          + "".join(f"\n  batch phase {d['phase']}: {d['ms']:.1f} ms for the whole list" for d in batch))
    slow = [d for d in batch if d["ms"] > BATCH_MAX_MS]
    return (not slow, f"a batch phase took longer than {BATCH_MAX_MS} ms: " + ", ".join(f"{d['phase']} {d['ms']:.0f} ms" for d in slow))


def make_round(level, description, crews, checks, solutions, open_delay=OPEN_DELAY_S, **kw):
    return Round(level=level, description=description, scenario=personas_ch9.scenario_enter,
                 attacks={n: crew_run(n) for n in crews}, setup=lambda lv, cu: setup(lv, cu, open_delay),
                 teardown=teardown, people=fans, threads=160,
                 solutions=("defenses/ladder.py", *solutions), extra_checks=[*checks, gate_cost], **kw)


OVER_MERGED = {"household": (6, 6), "apartment": (4, 4), "shared_card": (2, 2)}      # Round 3: real people merged with others

# Thresholds come from measured runs (README, "Expected results"), with margin only where the run is a race
# (Round 0) or the draw depends on who claimed first (the units a crew finally holds can move by a pair or two).
ROUNDS = {
    0: make_round(0, "first come, first served behind Chapter 4's funnel", ["patient_farm"],
                  [attackers(patient_farm=(20, 50)), fairness(fan_share=(0.0, 0.6), fan_odds=(0.0, 0.7)), people()],
                  (), open_delay=12.0),
    1: make_round(1, "a raffle: guests out, one entry per account, one ticket each", ["account_farm"],
                  [attackers(account_farm=(24, 45)), fairness(fan_share=(0.2, 0.46), fan_odds=(0.15, 0.5), per_identity=(2.0, 3.6)),
                   people()], ("defenses/raffle_basics.py",), open_delay=22.0),
    2: make_round(2, "verified email at entry, trust-weighted tickets at the draw", ["account_farm", "aged_farm"],
                  [attackers(account_farm=(4, 18), aged_farm=(6, 22)),
                   fairness(fan_share=(0.4, 0.68), fan_odds=(0.4, 0.8), per_identity=(3.0, 4.5)),
                   people(stepped_up=(2, 2))], ("defenses/eligibility.py",)),
    3: make_round(3, "entity resolution: one entry per cluster", ["aged_farm", "jig_farm"],
                  [attackers(aged_farm=(0, 3), jig_farm=(0, 3)),
                   fairness(fan_share=(0.88, 1.0), fan_odds=(0.85, 1.15), per_identity=(2.0, 3.2)),
                   people(hurt=OVER_MERGED, stepped_up=(2, 2))], ("defenses/entity_resolution.py",),
                  allowed_fp=tuple(OVER_MERGED)),
    4: make_round(4, "evidence graph, claim holds and step-up, re-score after the draw", ["jig_farm", "spread_farm", "crowd"],
                  [attackers(jig_farm=(0, 2), spread_farm=(0, 2), crowd=(2, 12)),
                   fairness(fan_share=(0.78, 0.96), fan_odds=(0.9, 1.3), per_identity=(1.5, 2.6), held_max=0),
                   people(stepped_up=(4, 8), held_at_claim=(1, 3))], ("defenses/weak_link_graph.py",)),
}

if __name__ == "__main__":
    main(ROUNDS)
