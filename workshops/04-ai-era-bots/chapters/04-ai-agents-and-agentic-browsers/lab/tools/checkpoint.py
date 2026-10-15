"""
Round checkpoint for W4 Ch4 (AI Agents & Agentic Browsers). Declares the rounds and hands over to
checkpoint_core.

    python tools/checkpoint.py --round 2              # set level 2, run this round's agents next to the cohort
    python tools/checkpoint.py --round 2 --level 1    # the same agents against Round 1's defenses (the "before")
    python tools/checkpoint.py --round 2 --catch-up   # install solutions/round1..2 first (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Round N runs at DEFENSE_LEVEL N. The agents are a real Chromium driven by a small observe -> decide ->
act loop (attacks/agent/), so this needs the browser: `python -m playwright install chromium`, and
HEADLESS=1 with no display. Each round runs the agent that beats the PREVIOUS round's defense, plus
the one it should now stop:

    round  defense added                    agents run                           what you should see
    -----  -------------------------------  -----------------------------------  ----------------------------------
      1    declared agents may browse,      undeclared (stock Chrome), honest    the honest agent is refused; the
           not buy                          (declares itself)                    undeclared one buys: policy sorts
                                                                                 the cooperative, nothing more
      2    robotic sessions get the         undeclared, humanized                the stock agent meets a step-up it
           step-up                                                               cannot answer; the humanized one buys
      3    Web Bot Auth identity            forged (claim, replay, vouch),       every forgery is refused; the agent
                                            verified                             signed by a trusted operator buys
      4    mandates, step-up, device cap    fleet (fresh accounts, one machine)  the fleet answers the step-up and
                                                                                 is capped at PER_DEVICE_CAP units

Next to every agent the cohort shops (tools/personas_ch4.py): the starter's 40 shoppers, five more
people an agent defense can hurt (screen reader, voice control, an RPA macro, a first-timer) and two
agents that are welcome (`legit:agent_user`, signed by a trusted operator, with a mandate). A round passes
when its agents meet their expectation AND no shopper is blocked. A step-up a person answers is
friction, reported but not a failure.
"""

import statistics

from checkpoint_core import Round, main
import labclient
import personas_ch4 as cohort

FLEET_CAP = 2


def _decisions(prefix):
    items = labclient.admin("GET", "/lab/decisions", params={"actor": prefix, "limit": 5000})["items"]
    return [d for d in items if d["phase"] == "action:drop_buy"]


def _median(xs):
    return statistics.median(xs) if xs else 0


def cohort_report(agents_expected):
    """Print the cohort's side of the round; fail if the welcome agents do not get what the round promises."""
    def check(board, results, attacks):
        bought, total = cohort.agent_users(results)
        met, humans = cohort.friction(results)
        w2 = {}
        for prefix in ("bot:", "legit:agent_user", "human:"):
            w2[prefix] = _median([d["extra"].get("w2_shadow", 0) for d in _decisions(prefix)])
        gate = [d["ms"] for d in _decisions("human:")]
        p95 = statistics.quantiles(gate, n=20)[-1] if len(gate) >= 2 else _median(gate)
        print(f"\ncohort: welcome agents bought {bought}/{total} (expected {agents_expected}); "
              f"{len(met)}/{humans} people met the step-up and answered it" + (f" ({', '.join(sorted(set(met)))})" if met else ""))
        print(f"  W2 stack in shadow, median points at the purchase: agents {w2['bot:']:.0f}, welcome agents "
              f"{w2['legit:agent_user']:.0f}, people {w2['human:']:.0f} (it never decides)")
        print(f"  defender cost: gate time of a shopper's purchase, median {_median(gate):.1f} ms, p95 {p95:.1f} ms")
        return bought == agents_expected, f"welcome agents bought {bought}/{total}, this round expects {agents_expected}"
    return check


def fleet_capped(board, results, attacks):
    wins = attacks["fleet"]["succeeded"]
    return 1 <= wins <= FLEET_CAP, f"the fleet won {wins} unit(s); the device cap is {FLEET_CAP} (and the step-up is friction, not a wall: expect at least 1)"


ROUNDS = {
    1: Round(level=1, description="declared agents may browse, not buy", scenario="agent_drop",
             attacks={"undeclared": "attacks/round1_undeclared_agent.py", "honest": "attacks/round1_honest_agent.py"},
             expect={"undeclared": "full", "honest": "blocked"},
             extra_checks=[cohort_report(0)], solutions=("defenses/agent_policy.py",)),
    2: Round(level=2, description="robotic sessions get the step-up", scenario="agent_drop",
             attacks={"undeclared": "attacks/round1_undeclared_agent.py", "humanized": "attacks/round2_humanized_agent.py"},
             expect={"undeclared": "blocked", "humanized": "full"},
             extra_checks=[cohort_report(0)], solutions=("defenses/agent_behavior.py",)),
    3: Round(level=3, description="verified identity: signed by an operator we trust", scenario="agent_drop",
             attacks={"forged": "attacks/round3_forged_agent.py", "verified": "attacks/round3_verified_agent.py"},
             expect={"forged": "blocked", "verified": "full"},
             extra_checks=[cohort_report(2)], solutions=("defenses/agent_identity.py",)),
    4: Round(level=4, description="the checkout gate: mandates, step-up, device cap", scenario="agent_drop",
             attacks={"fleet": "attacks/round4_fleet.py"},
             extra_checks=[fleet_capped, cohort_report(2)], solutions=("defenses/checkout_gate.py",)),
}

if __name__ == "__main__":
    main(ROUNDS)
