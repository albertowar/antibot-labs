"""
Round checkpoint for W4 Ch11 (the capstone). Declares the rounds and hands over
to checkpoint_core.

    python tools/checkpoint.py --round 1              # run the round: legit mix + the round's attack, judge
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 first, then run
    python tools/checkpoint.py --restore              # put your own files back (the .bak copies)
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

    round  level  attacker                      the layer it tests          judged on
    -----  -----  ----------------------------  --------------------------  ------------------------------
      0      0    naive crawler + agent + reader  — (baseline; W1+W2 shadow) everything succeeds; 0 legit hurt
      1      1    the crawler fleet             crawl governance (L1)       impostors blocked, licensed pays,
                                                                            no free-path leak; search allowed
      2      2    the agent farm                agent governance (L2)       farm ≤ 2 drops; signed-untrusted
                                                                            and forged earn nothing
      3      3    LLM extractor + injector      deception + LLM guard (L3)  extractor poisoned; 0 injections
                                                                            land; crawlers/readers untouched

The capstone's legitimate traffic is the agent- and crawler-aware mix
(tools/legit_traffic.py): human shopper cohorts (incl. touch, autofill, a11y,
a person's own agent, a signed cloud agent with a mandate) AND the crawlers the
reservation protects (verified search, the paying training crawler, text-mode
readers, a prefetcher). It runs next to every round's attack and a block or
maze of any of them is a false positive the round fails on. The LLM is the
deterministic mock (tools/llm.py) unless LLM_URL points at a local model.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "attacks"))

import labclient  # noqa: E402  (runs the labnet guard; BASE_URL is the harness's store URL)
from checkpoint_core import Round, main  # noqa: E402

LAB_TIME_SCALE = os.environ.setdefault("LAB_TIME_SCALE", "0.05")


# --- attack-slot wrappers (each returns {attempted, succeeded, ...} for the harness) --------------

def _legit():
    import legit_traffic
    return legit_traffic.run_summary()


def _round0():
    import round0_naive
    r = round0_naive.run()
    crawl, agent, ex = r["crawler"], r["agent"], r["extract"]
    # baseline: the crawler harvests the catalogue, the agent buys, the extractor reads
    ok = crawl["products"] >= 118 and agent["succeeded"] >= 1 and ex["harvested"] >= 1
    return {"attempted": 3, "succeeded": int(ok) * 3, "crawler_products": crawl["products"],
            "agent_orders": agent["succeeded"], "extract_harvested": ex["harvested"]}


def _round1():
    import round1_crawler_fleet
    return round1_crawler_fleet.run()


def _round2():
    import round2_agent_farm
    return round2_agent_farm.run()


def _round3_extract():
    import round3_llm_extract
    return round3_llm_extract.run()


def _round3_inject():
    import round3_injector
    return round3_injector.run()


# --- Round 4: the integrated attack, the new-vendor onboarding, the audit ------------------------

NEW_VENDOR = "https://agents.newvendor.test"


def _round4_integrated():
    """The whole fleet again (crawler fleet + agent farm) plus the score-oracle prober."""
    import round4_integrated as r4
    base = labclient.BASE_URL
    r4.crawl_fleet = __import__("round1_crawler_fleet").run
    __import__("round1_crawler_fleet").run(base)
    farm = __import__("round2_agent_farm").run(base)
    probe = r4.score_oracle_probe(base)
    print(f"  score-oracle: {probe['scores_readable']}/{probe['attempted']} replies carried a score; "
          f"threshold {'RECOVERABLE' if probe['threshold_recoverable'] else 'not recoverable'}")
    return {"attempted": farm["attempted"], "succeeded": farm["succeeded"],
            "farm_placed": farm["succeeded"], "threshold_recoverable": probe["threshold_recoverable"],
            "scores_readable": probe["scores_readable"], "probes": probe["attempted"]}


def _vendor(tag):
    import round4_integrated as r4
    v = r4.new_vendor(labclient.BASE_URL, n=5)
    v["placed"] = v["succeeded"]
    print(f"  new vendor ({tag}): {v['succeeded']}/{v['attempted']} orders placed")
    return v


def _onboard():
    import approve
    approve.onboard(NEW_VENDOR, by="checkpoint", category="shopping-agent vendor")
    return {"attempted": 1, "succeeded": 1, "onboarded": NEW_VENDOR}


def _audit():
    import audit
    passed = audit.run(labclient.BASE_URL, record=os.path.join(os.path.dirname(HERE),
                                                                "solutions", "round4", "governance_record.md"))
    from record_checklist import score_record
    _rows, covered = score_record(os.path.join(os.path.dirname(HERE), "solutions", "round4", "governance_record.md"))
    return {"attempted": 7, "succeeded": passed, "cards_passed": passed, "record_covered": covered}


def round4_ops(board, results, attacks):
    integ = attacks.get("integrated") or {}
    vbefore = attacks.get("vendor_before") or {}
    vafter = attacks.get("vendor_after") or {}
    audit_r = attacks.get("audit") or {}
    bad = []
    if integ.get("farm_placed", 99) > 2:
        bad.append(f"the farm placed {integ.get('farm_placed')} drops (ceiling 2)")
    if integ.get("threshold_recoverable", True):
        bad.append(f"the score oracle is recoverable ({integ.get('scores_readable')}/{integ.get('probes')} "
                   "replies carried a score): the L4 oracle guard did not strip it")
    if vbefore.get("placed", 99) != 0:
        bad.append(f"the un-onboarded vendor placed {vbefore.get('placed')} orders (expected 0)")
    if vafter.get("placed", 0) < 1:
        bad.append("the onboarded vendor placed no orders (onboarding did not take effect)")
    if audit_r.get("cards_passed", 0) != 7:
        bad.append(f"governance audit {audit_r.get('cards_passed')}/7 cards")
    if audit_r.get("record_covered", 0) < 12:
        bad.append(f"governance record covers {audit_r.get('record_covered')}/12 checklist items")
    return (not bad), "; ".join(bad)


# --- false-positive gate: no legitimate cohort may be blocked or mazed ---------------------------

def no_legit_hurt(board, results, attacks):
    legit = attacks.get("legit") or {}
    hurt = legit.get("hurt") or []
    if hurt:
        who = ", ".join(f"{h['cohort']}/{h['persona']} ({h['outcome']})" for h in hurt[:6])
        return False, f"{len(hurt)} legitimate cohort(s) hurt: {who}"
    return True, ""


# --- per-round attack-side targets ----------------------------------------------------------------

def round0_baseline(board, results, attacks):
    r = attacks.get("naive") or {}
    if r.get("succeeded", 0) < 3:
        return False, (f"baseline not clean: crawler {r.get('crawler_products')}/120 products, "
                       f"agent {r.get('agent_orders')} orders, extractor {r.get('extract_harvested')} records")
    return True, ""


def round1_governed(board, results, attacks):
    r = attacks.get("fleet") or {}
    checks = [("training crawler free pages", r.get("training", {}).get("products", 99), 0),
              ("impostor pages", r.get("impostor", {}).get("products", 99), 0),
              ("stealth second-pass pages", r.get("stealth_pass2", {}).get("products", 99), 0),
              ("paying crawler charged pages", -r.get("paying", {}).get("charged_pages", 0), -1),
              ("free-path leaks", r.get("free_path_leaks", 99), 0)]
    bad = [f"{name} = {abs(got)}" for name, got, ceil in checks if got > ceil]
    return (not bad), "crawl governance leaked: " + "; ".join(bad)


def round2_farm_capped(board, results, attacks):
    r = attacks.get("farm") or {}
    placed = r.get("succeeded", 99)
    if placed > 2:
        return False, f"the farm placed {placed} drop orders (ceiling 2)"
    return True, ""


def round3_poisoned(board, results, attacks):
    ex, inj = attacks.get("extract") or {}, attacks.get("inject") or {}
    bad = []
    if ex.get("honeypot_hits", 0) < 1 or ex.get("canaries", 0) < 1:
        bad.append(f"extractor not poisoned (honeypots {ex.get('honeypot_hits')}, canaries {ex.get('canaries')})")
    if inj.get("hits", 99) != 0:
        bad.append(f"{inj.get('hits')}/{inj.get('total')} injections landed")
    return (not bad), "; ".join(bad)


ROUNDS = {
    0: Round(level=0, description="baseline: the naive fleet, W1+W2 in shadow",
             scenario=None, solutions=(),
             attacks={"naive": _round0, "legit": _legit},
             extra_checks=[round0_baseline, no_legit_hurt]),
    1: Round(level=1, description="the crawler fleet vs crawl governance",
             scenario=None, solutions=("defenses/crawl_governance.py",),
             attacks={"fleet": _round1, "legit": _legit},
             legit_hurt_max=0,
             extra_checks=[round1_governed, no_legit_hurt]),
    2: Round(level=2, description="the agent farm vs agent governance",
             scenario=None, solutions=("defenses/agent_governance.py", "policies/agent_policy.json"),
             attacks={"farm": _round2, "legit": _legit},
             legit_hurt_max=0,
             extra_checks=[round2_farm_capped, no_legit_hurt]),
    3: Round(level=3, description="LLM extractor + injector vs deception and the LLM guard",
             scenario=None,
             solutions=("defenses/deception_limits.py", "defenses/llm_guard.py"),
             attacks={"extract": _round3_extract, "inject": _round3_inject, "legit": _legit},
             legit_hurt_max=0,
             extra_checks=[round3_poisoned, no_legit_hurt]),
    4: Round(level=4, description="operate and audit: integrated attack, new-vendor onboarding, the audit",
             scenario=None, solutions=("defenses/oracle_guard.py",),
             attacks={"integrated": _round4_integrated, "vendor_before": lambda: _vendor("before onboarding"),
                      "onboard": _onboard, "vendor_after": lambda: _vendor("after onboarding"),
                      "legit": _legit, "audit": _audit},
             legit_hurt_max=0,
             extra_checks=[round4_ops, no_legit_hurt]),
}

if __name__ == "__main__":
    main(ROUNDS)
