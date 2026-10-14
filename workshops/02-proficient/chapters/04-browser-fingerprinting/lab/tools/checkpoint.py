"""
Round checkpoint for Chapter 4 (Browser Fingerprinting). Declares the rounds and hands over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run every bot next to the 40 shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same bots against level 2 (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N: level 0 is the bare store, and each level adds one layer
(defenses/ladder.py). Every round runs EVERY sign-up farm of the chapter, so you see both sides at each
level: the farms the current layers stop, and the ones that still get through (the next round's problem).
Each farm makes 10 sign-up attempts, each with a fresh browser and a new source address, and reports how
many accounts it created:

    full      >= 90 % of the attempts created an account
    partial   the first 3 accounts, then refused (the linking limit for a rare device)
    blocked   <= 10 %

Next to the farms, the 40 shoppers (tools/population.py with tools/personas_ch4.py) each sign up as
one real-browser profile: a refused shopper fails the round, except the no-JavaScript one from Round 1
on (it has no fingerprint, so it is refused by design: an accepted, measured cost). Shoppers the gate
only flagged (score 20-39, still served) are listed per cohort, as are your own captured profiles
(tools/profiles/you-*.json), which must never be refused.

Defender cost: the collector's run time and payload in a real Chromium (from the farms' own browsers) and,
per check, the milliseconds the gate spent on the sign-up (Server-Timing).

Catching up: the layers are pre-written, so `--catch-up` only installs the round's defenses/ladder.py
and policy.py from solutions/round<N>/. The checkpoint sets the level itself.

The farms share one store here, so Round 4 replays a second harvested PC (data/harvested_fp_b.json);
by hand, with a reset between attacks, the first PC gives the same result.

Needs Playwright: pip install -r requirements-browser.txt && python -m playwright install chromium
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402
import personas_ch4  # noqa: E402  (registers the "fp_signup" scenario)
from checkpoint_core import LAB, Round, main  # noqa: E402

SIGNUPS = 10
# name -> (script, the first level that stops it, accounts it still gets there)
BOTS = {
    "round1_headless_signup": ("attacks/round1_headless_signup.py", 1, 0),
    "round2_patched_signup": ("attacks/round2_patched_signup.py", 2, 0),
    "round3_replay_signup": ("attacks/round3_replay_signup.py", 3, 3),
    "round4_noise_signup": ("attacks/round4_noise_signup.py --payload attacks/data/harvested_fp_b.json", 4, 3),
}
# Shoppers the gate may flag (20-39, served) without failing a round: the noise-patching extension users
FLAGGED_OK = {"privacy-extension"}


def attack_spec(script):
    base, _, args = script.partition(" ")
    return f"{base} --signups {SIGNUPS} --no-reset {args}".strip()


def expected_created(name, level):
    first, still = BOTS[name][1], BOTS[name][2]
    return SIGNUPS if level < first else still


def expectation(name, level):
    created = expected_created(name, level)
    return "full" if created == SIGNUPS else ("blocked" if created == 0 else "partial")


def exact_counts(level):
    """Each farm creates exactly the accounts the layers allow: 0 once stopped, 3 at the linking limit."""
    def check(board, results, attacks):
        bad = []
        for name in BOTS:
            got = (attacks.get(name) or {}).get("succeeded")
            if got != expected_created(name, level):
                bad.append(f"{name}: {got} accounts created, expected {expected_created(name, level)}")
        return (not bad, "; ".join(bad))
    return check


def link_mode_is_rarity(board, results, attacks):
    mode = labclient.admin("GET", "/lab/fp/dashboard")["link_mode"]
    return (mode == "rarity", f"the store runs LINK_MODE={mode}; the expected results are for rarity "
                              f"(defenses/policy.py, or unset LINK_MODE)")


def p95(values):
    return statistics.quantiles(values, n=20)[-1] if len(values) >= 2 else values[0]


def shoppers(level):
    def check(board, results, attacks):
        print("\nshoppers by cohort                 users  refused  flagged (20-39)")
        problems = []
        for cohort, (users, blocked, flagged) in personas_ch4.summarize(results).items():
            print(f"  {cohort:<30}{users:>6}{blocked:>9}{flagged:>9}")
            if flagged and cohort not in FLAGGED_OK:
                problems.append(f"{flagged} {cohort} shopper(s) flagged but served")
        for r in results:
            if r.get("outcome") == "blocked" or r.get("verdict_name") == "monitor":
                print(f"    {r['outcome']:<10} {r.get('cohort')}: score {r.get('score')}  {r.get('signals')}")
        nojs = [r for r in results if r.get("cohort") == personas_ch4.NO_PROFILE]
        want = "blocked" if level >= 1 else "registered"
        if any(r.get("outcome") != want for r in nojs):
            problems.append(f"the no-JavaScript shopper should be {want} at level {level}")
        gate = [r["gate_ms"] for r in results if r.get("gate_ms") is not None]
        print("\ndefender cost")
        collect = [a["collect_ms"] for a in attacks.values() if a and a.get("collect_ms") is not None]
        sizes = [a["payload_bytes"] for a in attacks.values() if a and a.get("payload_bytes")]
        if collect:
            print(f"  collector (headless Chromium): median {statistics.median(collect):.0f} ms, "
                  f"payload {statistics.median(sizes) / 1024:.1f} KB")
        if gate:
            print(f"  gate on the sign-up: median {statistics.median(gate):.2f} ms, p95 {p95(gate):.2f} ms")
        for name in ("fp_gate", "render_stack", "lie_detector", "linking", "fuzzy_cluster"):
            ms = [r["timing"][name] for r in results if name in r.get("timing", {})]
            if ms:
                print(f"    {name:<14} median {statistics.median(ms):.2f} ms, p95 {p95(ms):.2f} ms")
        return (not problems, "; ".join(problems))
    return check


def your_profiles(level):
    def check(board, results, attacks):
        mine = personas_ch4.run_own()
        if not mine:
            print("\nyour profiles: none yet (open /lab/fp/check in your browser, download the profile into "
                  "tools/profiles/you-<browser>.json)")
            return (True, "")
        for r in mine:
            print(f"\nyour profile {r['cohort']}: {'created' if r['status'] == 201 else 'REFUSED'} "
                  f"(score {r['score']}) {r['signals']}")
        refused = [r["cohort"] for r in mine if r["status"] != 201]
        return (not refused, "your own browser would be refused: " + ", ".join(refused))
    return check


def make_round(n, description):
    return Round(level=n, description=description, scenario="fp_signup",
                 attacks={name: attack_spec(script) for name, (script, _, _) in BOTS.items()},
                 expect={name: expectation(name, n) for name in BOTS},
                 allowed_fp=(personas_ch4.NO_PROFILE,) if n >= 1 else (), bot_success_max=1.0,
                 extra_checks=[exact_counts(n), link_mode_is_rarity, shoppers(n), your_profiles(n)],
                 solutions=("defenses/ladder.py", "defenses/policy.py"))


ROUNDS = {
    0: make_round(0, "instrument: the collector records, nobody is refused"),
    1: make_round(1, "L1 a fingerprint is required + render-stack plausibility"),
    2: make_round(2, "L2 lie detection: page vs. worker vs. headers"),
    3: make_round(3, "L3 exact-ID linking, rarity-weighted"),
    4: make_round(4, "L4 fuzzy clustering on noise-resistant components"),
}

if __name__ == "__main__":
    main(ROUNDS)
