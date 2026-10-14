"""
Round checkpoint for W3 Ch6 (Specialized Attack Scenarios). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run this round's attackers next to the 40 shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same attackers against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N and each level includes the ones below it. Level 0 is the generic per-IP
bucket. Each round adds one scenario's signature and runs the attackers that scenario ships:

    round  defense added                           attackers run                           what you should see
    -----  --------------------------------------  --------------------------------------  ------------------------------
      1    breached-password step-up (a code)      stuffer                                 30 takeovers -> 0 · 2 shoppers stepped up
      2    funnel integrity + one unit per device  scalper, skip-view, patient              50 pairs -> 0 (patient: 4) · 40 shoppers buy
      3    honeypot SKUs + catalogue coverage      crawler, skip-hidden                    120 pages -> 0 / 20 · researcher untouched
      4    disposable + egress + device cluster    farm, clean-emails                      20 accounts -> 0 / 3 · 3 phones stepped up
      5    GIVT filters + SIVT engagement funnel   givt, sivt                             60 billed -> 0 / 0 · nobody filtered

Next to the attackers, the 40 shoppers of the starter run a scenario that mirrors the attack surface
(tools/personas_ch6.py). Defender cost is the gate time of the shoppers' own requests from the decision log.
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch6  # noqa: E402  (registers the ch6_* scenarios)
from checkpoint_core import Round, main  # noqa: E402
import labclient  # noqa: E402

GATE_MEDIAN_MAX_MS = 20.0           # defender-cost threshold: median gate time per shopper request (in-process Redis)
GATE_MEDIAN_MAX_MS_REDIS = 250.0    # with a real Redis the checks cost a network round trip each
WEAK = 30                           # seed users 000-029 reuse a top-30 password: the combo list's real hits
STOCK = 50                          # DROP_STOCK
DEVICES = 4                         # the scalper's device cookies
COVERAGE_CAP = 25
IP_CAP = 3                          # the farm's leak when it dodges the blocklist


def attackers(**want):
    """want: name -> (lo, hi) on the attacker's `succeeded`. Prints the line the README table is made of."""
    def check(board, results, attacks):
        bad = []
        print("\nattackers                  got   expected")
        for name, (lo, hi) in want.items():
            got = (attacks.get(name) or {}).get("succeeded", -1)
            print(f"  {name:<22}{got:>5}   {lo}-{hi}")
            if not lo <= got <= hi:
                bad.append(f"{name}: got {got}, expected {lo}-{hi}")
        return (not bad, "; ".join(bad))
    return check


def people(stepped_up=(0, 0), bought=None):
    """The false-positive accounting: who paid for this round's defenses."""
    lo, hi = stepped_up

    def check(board, results, attacks):
        rows = personas_ch6.summarize(results)
        n_step = sum(r["stepped_up"] for r in rows.values())
        n_hurt = sum(r["hurt"] for r in rows.values())
        per = ", ".join(f"{k} {v['stepped_up']}" for k, v in sorted(rows.items()) if v["stepped_up"]) or "none"
        print(f"\nthe people: {len(results)} shoppers · stepped up {n_step} ({per}) · hurt {n_hurt}")
        bad = []
        if not lo <= n_step <= hi:
            bad.append(f"{n_step} people stepped up, expected {lo}-{hi}")
        if bought is not None:
            got = board["summary"]["purchases"].get("human", 0)
            print(f"  humans who bought the drop: {got}/{len(results)}")
            if got < bought:
                bad.append(f"only {got} shoppers bought the drop, expected {bought}")
        return (not bad, "; ".join(bad))
    return check


def gate_cost(board, results, attacks):
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "actor": "human:"})["items"]
    ms = [d["ms"] for d in rows]
    if not ms:
        return (False, "no shopper requests in the decision log")
    median = statistics.median(ms)
    limit = GATE_MEDIAN_MAX_MS if labclient.admin("GET", "/lab/config")["redis_url"].startswith("memory") else GATE_MEDIAN_MAX_MS_REDIS
    p95 = statistics.quantiles(ms, n=20)[-1] if len(ms) > 1 else ms[0]
    print(f"defender cost (the shoppers' requests, while the attackers run)\n  gate per request: median {median:.2f} ms, p95 {p95:.2f} ms over {len(ms)} requests")
    return (median < limit, f"gate median {median:.2f} ms > {limit} ms")


def scalper_totals(board, results, attacks):
    bots = board["summary"]["purchases"].get("bot", 0)
    cap = DEVICES
    return (bots <= cap, f"bots bought {bots} pairs, at most {cap} (one per device) allowed")


def tiers(board, results, attacks):
    givt, sivt = attacks.get("givt") or {}, attacks.get("sivt") or {}
    print(f"  givt flood: {givt.get('givt_filtered')} filtered as GIVT · sivt fleet: {sivt.get('sivt_filtered')} filtered as SIVT (givt tags: {sivt.get('givt_filtered')})")
    ok = givt.get("givt_filtered") == givt.get("attempted") and sivt.get("sivt_filtered") == sivt.get("attempted")
    return (ok, "every GIVT click should carry a givt_* tag and every SIVT click a sivt_* tag only")


def canary(board, results, attacks):
    seen = [attacks[k].get("canary") for k in ("crawler", "trap_aware") if attacks.get(k)]
    return (all(seen), "the scraper's HTML should carry its per-session canary")


ATTACKS = {
    "stuffer": "attacks/round1_stuffer.py",
    "scalper": "attacks/round2_scalper.py",
    "skip_view": "attacks/round2_scalper.py --skip-view",
    "patient": "attacks/round2_scalper.py --patient",
    "crawler": "attacks/round3_scraper.py",
    "trap_aware": "attacks/round3_scraper.py --skip-hidden",
    "farm": "attacks/round4_account_farm.py",
    "clean_emails": "attacks/round4_account_farm.py --clean-emails",
    "givt": "attacks/round5_click_fraud.py",
    "sivt": "attacks/round5_click_fraud.py --sivt",
}


def make_round(level, description, scenario, attacks, solutions, checks, **kw):
    return Round(level=level, description=description, scenario=scenario, attacks={n: ATTACKS[n] for n in attacks},
                 solutions=("defenses/ladder.py", *solutions), extra_checks=[*checks, gate_cost], **kw)


ROUNDS = {
    1: make_round(1, "breached-password step-up: a right-but-leaked password earns a code", "ch6_login", ["stuffer"],
                  ("defenses/breached_passwords.py",),
                  [attackers(stuffer=(0, 0)), people(stepped_up=(2, 2))]),
    2: make_round(2, "funnel integrity and one unit per device", "ch6_drop", ["scalper", "skip_view", "patient"],
                  ("defenses/scalping_funnel.py",),
                  [attackers(scalper=(0, 0), skip_view=(0, 0), patient=(0, DEVICES)), scalper_totals, people(bought=40)],
                  metric="purchases", bot_success_max=0.1),
    3: make_round(3, "honeypot SKUs and catalogue coverage", "ch6_browse", ["crawler", "trap_aware"],
                  ("defenses/scrape_defense.py",),
                  [attackers(crawler=(0, 0), trap_aware=(COVERAGE_CAP - 5, COVERAGE_CAP - 5)), people(), canary]),
    4: make_round(4, "disposable domains, egress velocity and device clusters", "ch6_signup", ["farm", "clean_emails"],
                  ("defenses/account_cluster.py",),
                  [attackers(farm=(0, 0), clean_emails=(IP_CAP, IP_CAP)), people(stepped_up=(3, 3))]),
    5: make_round(5, "GIVT hard filters and the SIVT engagement funnel", "ch6_ads", ["givt", "sivt"],
                  ("defenses/ivt_scoring.py",),
                  [attackers(givt=(0, 0), sivt=(0, 0)), people(), tiers]),
}

if __name__ == "__main__":
    main(ROUNDS)
