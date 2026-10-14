"""
Round checkpoint for W2 Ch6 (Account Takeover & Credential Stuffing). Declares the rounds and hands
over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run this round's attackers next to the 142 people
    python tools/checkpoint.py --round 3 --level 2    # the same attackers against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N (level 0 is the bare store). Each round runs the attacker that
beats the PREVIOUS round's defense, plus the previous round's attacker to prove it is now dead:

    round  defense added                              attackers run                  what you should see
    -----  -----------------------------------------  -----------------------------  -----------------------------------
      0    none                                       naive                          30 of 30 accounts taken over
      1    per-IP velocity + per-account lockout      naive, distributed             naive ~0 · distributed ~30 · CGNAT hurt
      2    per-cohort failure / unknown ratios        distributed, clean-list        distributed ~0 · clean-list ~30
      3    breached-password step-up, oracle closed   clean-list, stealer            clean-list 0 · stealer 10 of 10
      4    device + network risk, fresh proof         stealer, replay                stealer 0 · replay reads 10, changes 0

Next to the attackers, 132 people sign in (tools/personas_ch6.py) plus the 10 victims of the
infostealer rounds. `hurt` is a person who ended without a session; `stepped up` is a person who
had to enter an emailed code and did; the 15 typos are rejected once, correctly, and are not a
false positive. The CGNAT cohort is the documented cost of Round 1 and carries forward.

Defender cost: the gate time of the PEOPLE's sign-ins from the decision log (everything the
defenses do while the attackers hammer the same store, not the PBKDF2 hash the login route pays).
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch6  # noqa: E402  (swaps in the sign-in cohort and the `ato_login` scenario)
from checkpoint_core import Round, main  # noqa: E402
import labclient  # noqa: E402

ATTACKS = {
    "naive": "attacks/round0_naive_stuffer.py",
    "distributed": "attacks/round1_distributed_stuffer.py",
    "cleanlist": "attacks/round2_clean_list_stuffer.py",
    "stealer": "attacks/round3_stealer_log_replay.py",
    "replay": "attacks/round4_session_replay.py",
}
GATE_MEDIAN_MAX_MS = 20.0       # defender-cost threshold: median gate time per sign-in (in-process Redis)
GATE_MEDIAN_MAX_MS_REDIS = 250.0   # with a real Redis: ~10 network round trips per sign-in under a 16-thread flood
WEAK = 30                       # accounts that reuse a breached password (seed users 000-029)
VICTIMS = 10


def ato(attacks, name):
    return (attacks.get(name) or {}).get("accounts_taken_over", -1)


def attackers(**want):
    """want: name -> (lo, hi) accounts taken over. Prints the line the README table is made of."""
    def check(board, results, attacks):
        bad = []
        print("\nattackers                  taken over")
        for name, (lo, hi) in want.items():
            got = ato(attacks, name)
            extra = ""
            if name == "replay":
                extra = f"   (read {attacks[name].get('accounts_read')} accounts, changed {attacks[name].get('sensitive_actions')})"
            print(f"  {name:<22}{got:>8}  expected {lo}-{hi}{extra}")
            if not lo <= got <= hi:
                bad.append(f"{name}: {got} accounts taken over, expected {lo}-{hi}")
        return (not bad, "; ".join(bad))
    return check


def replay_reads(read_min, change_max):
    def check(board, results, attacks):
        out = attacks.get("replay") or {}
        ok = out.get("accounts_read", 0) >= read_min and out.get("sensitive_actions", 99) <= change_max
        return (ok, f"stolen session: read {out.get('accounts_read')} (want >= {read_min}), changed {out.get('sensitive_actions')} (want <= {change_max})")
    return check


def people(cgnat_hurt, stepped_up):
    """The false-positive accounting: who paid for this round's defenses."""
    lo_c, hi_c = cgnat_hurt
    lo_s, hi_s = stepped_up

    def check(board, results, attacks):
        rows = personas_ch6.summarize(results)
        print("\nthe people                 n  hurt  stepped up  typo rejected")
        for persona, r in sorted(rows.items()):
            print(f"  {persona:<18}{r['people']:>6}{r['hurt']:>6}{r['stepped_up']:>12}{r['typo_rejected']:>15}")
        stepped = sum(r["stepped_up"] for r in rows.values())
        bad = []
        if not lo_c <= rows["cgnat"]["hurt"] <= hi_c:
            bad.append(f"CGNAT cohort: {rows['cgnat']['hurt']} refused, expected {lo_c}-{hi_c}")
        if not lo_s <= stepped <= hi_s:
            bad.append(f"{stepped} people stepped up, expected {lo_s}-{hi_s}")
        if rows["typo"]["typo_rejected"] != rows["typo"]["people"]:
            bad.append("every typo should have been rejected once with a 401")
        return (not bad, "; ".join(bad))
    return check


def gate_cost(board, results, attacks):
    rows = labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "path": "/api/login", "actor": "human:"})["items"]
    ms = [d["ms"] for d in rows]
    if not ms:
        return (False, "no human sign-ins in the decision log")
    median = statistics.median(ms)
    limit = GATE_MEDIAN_MAX_MS if labclient.admin("GET", "/lab/config")["redis_url"].startswith("memory") else GATE_MEDIAN_MAX_MS_REDIS
    p95 = statistics.quantiles(ms, n=20)[-1] if len(ms) > 1 else ms[0]
    print(f"\ndefender cost (the people's sign-ins, while the attackers run)\n  gate per sign-in: median {median:.2f} ms, p95 {p95:.2f} ms over {len(ms)} requests")
    return (median < limit, f"gate median {median:.2f} ms > {limit} ms")


def make_round(level, description, attacks, solutions, checks):
    return Round(level=level, description=description, scenario="ato_login",
                 attacks={name: ATTACKS[name] for name in attacks}, allowed_fp=(personas_ch6.CGNAT,) if level >= 1 else (),
                 extra_checks=[*checks, gate_cost], solutions=solutions)


ROUNDS = {
    0: make_round(0, "bare store: nothing limits a login", ["naive"], (),
                  [attackers(naive=(WEAK - 2, WEAK)), people((0, 0), (0, 0))]),
    1: make_round(1, "L1 per-IP velocity + per-account lockout", ["naive", "distributed"],
                  ("defenses/ladder.py", "defenses/login_throttle.py"),
                  [attackers(naive=(0, 3), distributed=(WEAK - 4, WEAK)), people((2, 9), (0, 0))]),
    2: make_round(2, "L2 per-cohort failure and unknown-account ratios", ["distributed", "cleanlist"],
                  ("defenses/ladder.py", "defenses/population_signals.py"),
                  [attackers(distributed=(0, 3), cleanlist=(WEAK - 4, WEAK)), people((2, 9), (0, 0))]),
    3: make_round(3, "L3 breached-password step-up + the recover oracle closed", ["cleanlist", "stealer"],
                  ("defenses/ladder.py", "defenses/breached_passwords.py", "defenses/oracles.py"),
                  [attackers(cleanlist=(0, 0), stealer=(VICTIMS - 1, VICTIMS)), people((2, 9), (10, 12))]),
    4: make_round(4, "L4 device + network risk, fresh proof for sensitive changes", ["stealer", "replay"],
                  ("defenses/ladder.py", "defenses/risk_engine.py"),
                  [attackers(stealer=(0, 0), replay=(0, 0)), replay_reads(VICTIMS - 1, 0), people((2, 9), (28, 34))]),
}

if __name__ == "__main__":
    main(ROUNDS)
