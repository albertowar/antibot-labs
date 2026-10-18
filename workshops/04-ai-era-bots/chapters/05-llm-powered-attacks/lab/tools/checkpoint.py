"""
Round checkpoint for W4 Ch5 (LLM-Powered Attacks). Declares the rounds and hands over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run this round's attack next to the shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same attack against Round 2's defenses (the "before")
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N (level 0 is the store as it shipped: a honeypot SKU; level 1 wires the pre-written
content heuristics next to review_signals).
Each round runs the LLM attack that beats the previous round's defense, next to real customers doing the same
ordinary action the attacker abuses (tools/personas_ch5.py):

    round  defense you add          LLM attack                                  what you should see
    -----  -----------------------  ------------------------------------------  --------------------------------------
      0    none (as shipped)        (shoppers only)                             all 40 shoppers buy
      1    review_signals           40 unique reviews from 40 new accounts      published 40 -> 0; no real reviewer refused
      2    challenge_policy         puzzle solver registering 40 accounts       created 40 -> 0; humans challenged 20 -> few
      3    extractor_traps          text extractor harvesting the catalogue     harvest poisoned: canary, honeypot hit
      4    llm_guard                prompt injection through reviews            reaching a customer 9 -> 0; 3 reviewers freed

"Hurt" means refused (403) or stuck on a puzzle. A *held* review (202) and a puzzle a person solves are
friction, not harm: the checkpoint reports them next to the pass/fail, and the scoreboard counts a hold in its
own `held` column (contract 1.6: an ext setting g.outcome).

Defender cost: the median gate time of the shoppers' requests from the decision log, and the LLM tokens the
store spends and the attacker spends.
"""

import os
import re
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import personas_ch5  # noqa: E402,F401  (swaps in the chapter's scenarios)
import scoreboard as sb  # noqa: E402
from checkpoint_core import Round, main  # noqa: E402
import labclient  # noqa: E402

GATE_MEDIAN_MAX_MS = 25.0           # defender-cost threshold: median gate time per shopper request (in-process Redis)
GATE_MEDIAN_MAX_MS_REDIS = 250.0    # with a real Redis: a few network round trips per request
FARM_CEILING = 3
SOLVER_CEILING = 2
HUMANS_CHALLENGED_MAX = 3           # Round 2, solution: a few shared-address shoppers may meet a puzzle


# --- the scoreboard, with the chapter's custom outcome column ---------------------------------------

_render = sb.render


def render(board, markdown=False):
    held = {}
    for a in board["actors"]:
        if a["kind"] in ("human", "bot") and a.get("held"):
            held[a["kind"]] = held.get(a["kind"], 0) + a["held"]
    note = f"held for moderation (the `held` outcome column): bots {held.get('bot', 0)}, shoppers {held.get('human', 0)}"
    return _render(board, markdown) + "\n" + (f"**{note}**" if markdown else note)


sb.render = render          # checkpoint_core calls scoreboard.render(board, markdown) for every round, "before" runs too


# --- checks -----------------------------------------------------------------------------------------

def _human_decisions():
    return labclient.admin("GET", "/lab/decisions", params={"limit": 5000, "actor": "human:"})["items"]


def gate_cost(board, results, attacks):
    ms = sorted(d["ms"] for d in _human_decisions())
    if not ms:
        return (False, "no shopper requests in the decision log")
    median = statistics.median(ms)
    limit = GATE_MEDIAN_MAX_MS if labclient.admin("GET", "/lab/config")["redis_url"].startswith("memory") else GATE_MEDIAN_MAX_MS_REDIS
    print(f"\ndefender cost (the shoppers' requests, while the attack runs)\n"
          f"  gate per request: median {median:.2f} ms, p95 {ms[int(len(ms) * 0.95)]:.2f} ms over {len(ms)} requests")
    return (median < limit, f"gate median {median:.2f} ms > {limit} ms")


def friction(board, results, attacks):
    """Held reviews and puzzles a person solved: not hurt, but never free. Printed, not judged."""
    held = sum(r.get("outcome") == "held" for r in results)
    challenged = sum(bool(r.get("challenged")) for r in results)
    print(f"\nfriction on real customers: {held} review(s) held for moderation, {challenged} puzzle(s) solved, "
          f"{sum(r.get('outcome') in ('stuck_on_challenge', 'blocked') for r in results)} refused")
    return (True, "")


def farm_ceiling(board, results, attacks):
    n = attacks["farm"]["succeeded"]
    a = attacks["farm"]
    print(f"\nfarm: {n} of {a['attempted']} reviews published, {a['held']} held, {a['blocked']} refused (ceiling {FARM_CEILING})")
    return (n <= FARM_CEILING, f"{n} fake reviews published (ceiling {FARM_CEILING})")


def solver_ceiling(board, results, attacks):
    a = attacks["solver"]
    humans = sum(bool(r.get("challenged")) for r in results)
    print(f"\nsolver: {a['succeeded']} of {a['attempted']} accounts created (ceiling {SOLVER_CEILING}); {a['served']} puzzles served, "
          f"~{a['tokens_per_solve']} tokens per solve\nhumans: {humans} of {len(results)} met a puzzle")
    bad = []
    if a["succeeded"] > SOLVER_CEILING:
        bad.append(f"{a['succeeded']} bot accounts created (ceiling {SOLVER_CEILING})")
    return (not bad, "; ".join(bad))


def humans_challenged(board, results, attacks):
    """Round 2's second bar: a solution serves on risk. The stub (a puzzle for everyone) fails this one too."""
    humans = sum(bool(r.get("challenged")) for r in results)
    return (humans <= HUMANS_CHALLENGED_MAX, f"{humans} of {len(results)} real customers were served a puzzle (max {HUMANS_CHALLENGED_MAX}): serve on risk")


def extractor_poisoned(board, results, attacks):
    a = attacks["extractor"]
    print(f"\nextractor: harvested {a['harvested']} records; honeypot pages fetched {a['honeypot_hits']}, "
          f"canaries carried {a['canaries']}, {a['tokens']} tokens spent")
    bad = []
    if a["honeypot_hits"] < 1:
        bad.append("the extractor never fetched a honeypot page: no hidden_records reached it")
    if a["canaries"] < 1:
        bad.append("no record carries the canary lot_code")
    return (not bad, "; ".join(bad))


def traps_aria_hidden(board, results, attacks):
    """Negative control: the off-screen block must be aria-hidden, or the screen-reader cohort hears the decoys."""
    html = labclient.requests.get(f"{labclient.BASE_URL}/products?page=1", timeout=10).text
    m = re.search(r'<div id="catalogue-notes"([^>]*)>', html)
    if m is None:
        return (True, "")                       # no traps wired yet: nothing to announce
    return ('aria-hidden="true"' in m.group(1), "the off-screen block is not aria-hidden: screen readers would read your decoys")


def injection_report(board, results, attacks):
    a = attacks["injector"]
    toks = {"bot": 0, "human": 0}
    for d in labclient.admin("GET", "/lab/decisions", params={"limit": 5000})["items"]:
        toks[d["actor"].split(":")[0]] = toks.get(d["actor"].split(":")[0], 0) + (d["extra"].get("tokens") or 0)
    print(f"\ninjector: {a['succeeded']}/{a['attempted']} variants reached a customer-facing response "
          f"({a['published']} reviews published, {a['held']} held, {a['refused']} refused); "
          f"the store spent {toks.get('bot', 0)} LLM tokens answering the bot")
    return (True, "")


def detector_aside(board, results, attacks):
    """The aside the chapter's debrief leans on: a toy AI-text detector flags careful human prose and misses casual bot prose."""
    sys.path.insert(0, os.path.join(os.path.dirname(HERE), "attacks"))
    from defenses.content_heuristics import looks_generated
    import round1_review_farm as farm
    from _common import catalogue
    from llm import LLM
    humans = [r["text"] for r in personas_ch5.TEXTS["round1"]]
    bots = [farm.review_text(LLM(), i, name) for i, (_sku, name) in enumerate(catalogue(40))]
    h, b = sum(map(looks_generated, humans)), sum(map(looks_generated, bots))
    print(f"\n[aside] toy AI-text detector flagged {h}/{len(humans)} human reviews and {b}/{len(bots)} bot reviews as 'generated':\n"
          f"        a reason to score the account and the traffic, not the writing")
    return (True, "")


def rnd(level, description, scenario, attacks, expect, solutions, checks, **kw):
    n = kw.get("population_n")
    return Round(level=level, description=description, scenario=scenario, attacks=attacks, expect=expect,
                 solutions=solutions, extra_checks=[*checks, friction, gate_cost],
                 people=lambda: personas_ch5.personas(n=n), **kw)


ROUNDS = {
    0: Round(level=0, description="the store as it shipped: a honeypot SKU, nothing else", scenario="browse",
             extra_checks=[gate_cost], people=personas_ch5.personas),
    1: rnd(1, "L1 review_signals: account age, purchase, device and egress velocity", "review_r1",
           {"farm": "attacks/round1_review_farm.py"}, {"farm": "blocked"}, ("defenses/review_signals.py",),
           [farm_ceiling, detector_aside], population_n=20),
    2: rnd(2, "L2 challenge_policy: serve on risk, meter with PoW, a solve is not a pass", "register",
           {"solver": "attacks/round2_llm_solver.py"}, {"solver": "blocked"}, ("defenses/challenge_policy.py",),
           [solver_ceiling, humans_challenged], population_n=20),
    3: rnd(3, "L3 extractor_traps: honeypot records, a canary instruction, decoys", "catalog",
           {"extractor": "attacks/round3_llm_extract.py"}, {"extractor": "blocked"}, ("defenses/extractor_traps.py",),
           [extractor_poisoned, traps_aria_hidden]),
    4: rnd(4, "L4 llm_guard: spotlighting, output validation, least privilege", "review_r4",
           {"injector": "attacks/round4_injector.py"}, {"injector": "blocked"}, ("defenses/llm_guard.py",),
           [injection_report], population_n=20),
}

if __name__ == "__main__":
    main(ROUNDS)
