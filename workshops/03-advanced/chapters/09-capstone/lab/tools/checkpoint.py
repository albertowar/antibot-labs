"""
Round checkpoint for the W3 capstone. Declares the rounds and hands over to checkpoint_core.

    python tools/checkpoint.py --round 2              # set round 2's level, run every attack next to the 43 people
    python tools/checkpoint.py --round 2 --level 5    # the same attacks against the level below (the "before" column)
    python tools/checkpoint.py --round 2 --catch-up   # install solutions/round1..2 (your files kept as .bak)
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

This lab is PRE-WRITTEN (level style) with three small exercises: every layer ships complete, and Rounds 1 to 3 each
leave one number for you to set (`TODO (Round N)`: api_hardening.py, stream_detectors.py, supply_chain.py), with the
answer in solutions/roundN/. `--catch-up` installs those answers cumulatively, so the checkpoint can be run at any
round without having done the ones before it. The checkpoint sets the store's level for you.

    round  level  the attack it must stop                              the layer
    -----  -----  ---------------------------------------------------  --------------------------------------------
      0      4    requests, curl_cffi, stock Chromium                   L0..L4: the inherited Workshop 2 stack
      1      5    introspection, a batch scrape, the REST walk,         L5: API hardening (api_hardening.py)
                  a WebSocket flood
      2      6    a micro-burst, a low-and-slow poll                    L6: streaming (stream_detectors.py)
      3      7    a form skimmer                                        L7: CSP connect-src (supply_chain.py)
      4      7    recon -> evade -> purchase                            the whole stack, read as a kill chain

Every round runs EVERY attack, so you see both what the current layers stop and what still gets through (the next
round's problem). The 43 people (tools/personas_api.py: the 40 shoppers of the W2 Ch9 lab, plus a mobile app, a second
phone and a partner integration) buy the drop and use the API in the same minute:

    blocked      a false positive: the round FAILS on any blocked person (the no-JavaScript visitor is the accepted
                 cost of the sensor gate, as in W2 Ch1 and Ch3)
    challenged   friction, listed per profile: the round fails above the round's budget

Defender cost: the gate's time on the drop POST (Server-Timing), which from level 6 includes the stream's inline work.

Needs Chromium for Round 0's stock-browser bot and Round 3's browser proof: python -m playwright install chromium
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402
import personas_api  # noqa: E402,F401  (registers the "capstone" scenario and adds the API clients)
from checkpoint_core import Round, main  # noqa: E402

# The drop gets 200 pairs for the checkpoint (the story says 50) so that bots and shoppers never compete for stock
# here: who gets the last pair is not this chapter's question. (STORE_CONTRACT: a lab cannot change the default,
# but POST /lab/reset takes ?stock=.)
CHECKPOINT_STOCK = 200
_reset = labclient.reset
labclient.reset = lambda mode="state", **params: _reset(mode, **dict({"stock": CHECKPOINT_STOCK}, **params))

LEVELS = {0: 4, 1: 5, 2: 6, 3: 7, 4: 7}

# name -> (script and flags, the ROUND from which it must be stopped)
BOTS = {
    "round0_requests": ("attacks/round0_naive.py --tool requests", 0),
    "round0_curl_cffi": ("attacks/round0_naive.py --tool curl_cffi", 0),
    "round0_playwright": ("attacks/round0_naive.py --tool playwright", 0),
    "round1_introspection": ("attacks/round1_api.py --technique introspection", 1),
    "round1_batch": ("attacks/round1_api.py --technique batch", 1),
    "round1_rest": ("attacks/round1_api.py --technique rest", 1),
    "round1_ws": ("attacks/round1_api.py --technique ws", 1),
    "round2_burst": ("attacks/round2_streaming.py --pattern burst", 2),
    "round2_slow": ("attacks/round2_streaming.py --pattern slow", 2),
    "round3_skimmer": ("attacks/round3_skimmer.py", 3),
    "round4_integrated": ("attacks/round4_integrated.py", 2),     # three stages: each layer stops its own, none left by level 6
}
# The layer that must be the one doing the stopping once the round is reached (a signal prefix in X-Lab-Signals).
STOPPED_BY = {"round1_introspection": "api_hardening:", "round1_batch": "api_hardening:", "round1_rest": "api_hardening:",
              "round2_burst": "streaming:", "round2_slow": "streaming:"}
# recon -> L5, evade -> L6, purchase -> L0 (the W2 layers that also fire on a bare purchase are not asked about)
KILL_CHAIN = {"recon": ["L5"], "evade": ["L6"], "purchase": ["L0"]}

# People that may meet the "proof" challenge in a round (friction, not a loss: they solve it and buy). Measured on the
# W2 Ch9 stack: the privacy-extension user (Chapter 1's lie detection reads the extension's wrapped navigator), the
# voice-control user (a teleported click, text without keys: Chapter 3's own cost) and the password-manager user who
# buys in 1.2 to 1.6 s (flow's dwell line). The W3 layers add none: an API client cannot solve a challenge, so for
# the three of them any challenge or block is a loss.
FRICTION_BUDGET = {0: 3, 1: 3, 2: 3, 3: 3, 4: 3}


def bot_expectations(rnd):
    """Stopped (<= 10 % succeeded) from its round on; below it a bot must still get through at least once ('some')."""
    return {name: "blocked" if rnd >= first else "some" for name, (_, first) in BOTS.items()}


def people(rnd):
    def check(board, results, attacks):
        by = {}
        for r in results:
            row = by.setdefault(r.get("behavior", "?"), {"n": 0, "challenged": 0, "blocked": 0, "done": 0})
            row["n"] += 1
            row["challenged"] += bool(r.get("challenged"))
            row["blocked"] += r.get("outcome") == "blocked"
            row["done"] += r.get("outcome") in ("bought", "browsed")
        print("\npeople by behavior profile         n  done  challenged  blocked")
        for name, row in sorted(by.items()):
            print(f"  {name:<30}{row['n']:>3}{row['done']:>6}{row['challenged']:>12}{row['blocked']:>9}")
        for r in results:
            if r.get("challenged") or r.get("outcome") == "blocked":
                print(f"    {r.get('outcome'):<8} {'(challenged) ' if r.get('challenged') else ''}{r.get('profile')}/{r.get('behavior')}: "
                      f"score {r.get('score')}  {r.get('signals')}")
        gate = [r["gate_ms"] for r in results if r.get("gate_ms") is not None]
        if gate:
            print(f"defender cost: gate median {statistics.median(gate):.2f} ms, max {max(gate):.2f} ms on the drop POST")
        challenged = sum(bool(r.get("challenged")) for r in results)
        budget = FRICTION_BUDGET[rnd]
        # A person that ended in an error is not "blocked", and a report that only counted blocks would stay green while
        # the store failed them. Every person must finish: buy, find the drop sold out, or (an API client) get their data.
        unfinished = [r for r in results if r.get("outcome") not in ("bought", "sold_out", "browsed") and r.get("persona") != "no_js"]
        for r in unfinished:
            print(f"    UNFINISHED {r.get('actor')}: {r.get('outcome')} {r.get('status')} {r.get('error', '')} {r.get('stage', '')}")
        return (challenged <= budget and not unfinished,
                f"{challenged} shoppers met the proof challenge, budget {budget}" if challenged > budget
                else f"{len(unfinished)} people did not finish what they came to do")
    return check


def stopped_by_the_right_layer(rnd):
    """From its round on, each API and stream attack is refused by ITS layer (not by an earlier one by accident)."""
    def check(board, results, attacks):
        wrong = [name for name, prefix in STOPPED_BY.items()
                 if rnd >= BOTS[name][1] and not any(s.startswith(prefix) for s in (attacks.get(name) or {}).get("signals", []))]
        return not wrong, "refused, but not by the layer this round teaches: " + ", ".join(wrong)
    return check


def kill_chain(rnd):
    def check(board, results, attacks):
        chain = (attacks.get("round4_integrated") or {}).get("kill_chain")
        ok = rnd < 3 or (chain is not None and all(set(want) <= set(chain.get(stage, [])) for stage, want in KILL_CHAIN.items())
                         and chain["recon"] == ["L5"] and chain["evade"] == ["L6"])
        print(f"\nkill chain: {chain}")
        return ok, f"the kill chain should be {KILL_CHAIN} (purchase may carry more layers), got {chain}"
    return check


def skimmer_proof(rnd):
    def check(board, results, attacks):
        proof = (attacks.get("round3_skimmer") or {}).get("browser_proof", "skipped")
        ok = rnd < 3 or proof == "skipped" or proof == "CSP refused the exfil in Chromium, same-origin telemetry still worked"
        return ok, f"a real browser disagrees with the header check: {proof}"
    return check


def make_round(n, description, solutions=()):
    return Round(level=LEVELS[n], description=description, scenario="capstone",
                 attacks={name: script for name, (script, _) in BOTS.items()},
                 expect=bot_expectations(n), allowed_fp=("no_js",),
                 extra_checks=[people(n), stopped_by_the_right_layer(n), kill_chain(n), skimmer_proof(n)],
                 solutions=solutions)


ROUNDS = {
    0: make_round(0, "naive fleet vs the inherited Workshop 2 stack (levels 1 to 4)"),
    1: make_round(1, "API abuse vs API hardening", ("defenses/api_hardening.py",)),
    2: make_round(2, "streaming evasion vs the stream detectors", ("defenses/stream_detectors.py",)),
    3: make_round(3, "form skimmer vs CSP connect-src", ("defenses/supply_chain.py",)),
    4: make_round(4, "the integrated assault vs the whole stack"),
}

if __name__ == "__main__":
    main(ROUNDS)
