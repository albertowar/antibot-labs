"""
Round checkpoint for Chapter 9 (the capstone). Declares the rounds and hands over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set round 3's level, run every scalper next to the 40 shoppers
    python tools/checkpoint.py --round 3 --level 3    # the same scalpers against Round 2's level (the "before" column)
    python tools/checkpoint.py --round 3 --catch-up   # install solutions/round1..3 (ladder.py, policy.py), your files kept as .bak
    python tools/checkpoint.py --restore              # put your own files back
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

This lab is PRE-WRITTEN: every layer ships complete (most of them are the finished checks of Chapters 1,
3, 5 and 6, copied byte for byte: shared.json), and a round is a DEFENSE_LEVEL. Catching up means running
the round at its level, which the checkpoint does for you; `--catch-up` additionally restores the reference
ladder.py and policy.py, undoing your experiments with weights and lines.

One offset to remember: Round N runs at DEFENSE_LEVEL N+1, because the W2 starter's level 0 is the bare
store (by contract) and Round 0's layer is therefore level 1. So the "before" column of Round N is
`--level N`, the previous round's level.

    round  level  the scalper it must stop            the layer
    -----  -----  ---------------------------------  -------------------------------------------------
      0      1    requests, curl_cffi, stock Chromium  headers, TLS consistency (claimed JA4), no-JS, webdriver
      1      2    headless Patchright                  fingerprint coherence (W2 Ch1 layers 2 and 3)
      2      3    scripted Camoufox                    behavior (W2 Ch3) and flow (server-measured)
      3      4    humanized Camoufox + account farm    the session and account model
      4      5    credential stuffing                  login token binding, failures per fingerprint cluster

Every round runs EVERY scalper, so you see both what the current layers stop and what still gets through
(the next round's problem). The 40 shoppers (tools/personas_ch9.py) buy the same drop in the same minute:

    blocked      a false positive: the round FAILS on any blocked shopper (the no-JavaScript visitor is the
                 accepted cost of the sensor gate, as in W2 Ch1 and Ch3)
    challenged   friction, listed per profile: the round fails above the round's budget

Defender cost: the gate's time on the drop POST (Server-Timing) and, from Round 3, the model's.

Needs the browsers: pip install -r requirements-browser.txt && python -m playwright install chromium &&
python -m patchright install chromium && python -m camoufox fetch
"""

import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402
import personas_ch9  # noqa: E402,F401  (registers the "ch9_drop" scenario)
from checkpoint_core import Round, main  # noqa: E402

# The drop gets 200 pairs for the checkpoint (the story says 50) so that bots and shoppers never compete for
# stock here: who gets the last pair is not this chapter's question. (STORE_CONTRACT: a lab cannot change
# the default, but POST /lab/reset takes ?stock=.)
CHECKPOINT_STOCK = 200
_reset = labclient.reset
labclient.reset = lambda mode="state", **params: _reset(mode, **dict({"stock": CHECKPOINT_STOCK}, **params))

# name -> (script and flags, the ROUND from which it must be stopped; None = never here)
BOTS = {
    "round0_requests": ("attacks/round0_naive.py --tool requests", 0),
    "round0_curl_cffi": ("attacks/round0_naive.py --tool curl_cffi", 0),
    "round0_playwright": ("attacks/round0_naive.py --tool playwright", 0),
    "round1_patchright": ("attacks/round1_patchright.py --sessions 2", 1),
    "round2_camoufox": ("attacks/round2_camoufox.py --sessions 2", 2),
    "round3_farm": ("attacks/round3_humanized_farm.py --sessions 3", 3),
    "round4_stuffing": ("attacks/round4_stuffing.py", 4),
    "round4_stuffing_token": ("attacks/round4_stuffing.py --with-token", 4),
    "round4_stuffing_rotate": ("attacks/round4_stuffing.py --with-token --rotate-fp", 4),   # the campaign step-up's row
}
# Shoppers that may meet the "proof" challenge in a round (friction, not a loss: they solve it and buy). Measured:
# from Round 1 the privacy-extension user (Chapter 1's lie detection reads the extension's wrapped navigator),
# from Round 2 also the voice-control user (teleported click, text without keys: Chapter 3's own cost) and the
# password-manager user who buys in 1.2 to 1.6 s (flow's dwell line).
FRICTION_BUDGET = {0: 0, 1: 1, 2: 3, 3: 3, 4: 3}


def bot_expectations(rnd):
    """Stopped (<= 10 % succeeded) from its round on; below it a bot must still get through at least once ('some')."""
    out = {}
    for name, (_, first) in BOTS.items():
        out[name] = "blocked" if first is not None and rnd >= first else "some"
    return out


def shoppers(rnd):
    def check(board, results, attacks):
        by = {}
        for r in results:
            row = by.setdefault(r.get("behavior", "?"), {"n": 0, "challenged": 0, "blocked": 0, "bought": 0})
            row["n"] += 1
            row["challenged"] += bool(r.get("challenged"))
            row["blocked"] += r.get("outcome") == "blocked"
            row["bought"] += r.get("outcome") == "bought"
        print("\nshoppers by behavior profile       n  bought  challenged  blocked")
        for name, row in sorted(by.items()):
            print(f"  {name:<30}{row['n']:>3}{row['bought']:>8}{row['challenged']:>12}{row['blocked']:>9}")
        for r in results:
            if r.get("challenged") or r.get("outcome") == "blocked":
                print(f"    {r.get('outcome'):<8} {'(challenged) ' if r.get('challenged') else ''}{r.get('profile')}/{r.get('behavior')}: "
                      f"score {r.get('score')}  {r.get('signals')}")
        gate = [r["gate_ms"] for r in results if r.get("gate_ms") is not None]
        if gate:
            print(f"defender cost: gate median {statistics.median(gate):.2f} ms, max {max(gate):.2f} ms on the drop POST")
        challenged = sum(bool(r.get("challenged")) for r in results)
        budget = FRICTION_BUDGET[rnd]
        # A shopper that ended in an error is not "blocked", and a report that only counted blocks would stay
        # green while the store failed them (the old lab's two databases did exactly that). Every shopper
        # must finish: buy, or find the drop sold out. The no-JavaScript visitor's refusal is the accepted cost.
        unfinished = [r for r in results if r.get("outcome") not in ("bought", "sold_out") and r.get("persona") != "no_js"]
        for r in unfinished:
            print(f"    UNFINISHED {r.get('actor')}: {r.get('outcome')} {r.get('status')} {r.get('error', '')}")
        return (challenged <= budget and not unfinished,
                f"{challenged} shoppers met the proof challenge, budget {budget}" if challenged > budget
                else f"{len(unfinished)} shoppers did not finish their purchase")
    return check


def make_round(n, description):
    return Round(level=n + 1, description=description, scenario="ch9_drop",
                 attacks={name: script for name, (script, _) in BOTS.items()} | (
                     {"round4_token_farm": "attacks/round4_token_farm.py --attempts 7"} if n >= 4 else {}),
                 expect=bot_expectations(n), allowed_fp=("no_js",),
                 extra_checks=[shoppers(n)], solutions=("defenses/ladder.py", "defenses/policy.py"))


ROUNDS = {
    0: make_round(0, "naive fleet vs headers, TLS consistency and the sensor gate"),
    1: make_round(1, "headless Patchright vs fingerprint coherence"),
    2: make_round(2, "scripted Camoufox vs behavior and flow"),
    3: make_round(3, "humanized Camoufox farm vs the session and account model"),
    4: make_round(4, "credential stuffing vs token binding and cluster risk"),
}

if __name__ == "__main__":
    main(ROUNDS)
