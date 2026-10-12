"""
Round checkpoint for Chapter 3 (Behavioral Analysis). Declares the rounds and hands over to checkpoint_core.

    python tools/checkpoint.py --round 3              # set level 3, run every bot next to the 40 shoppers
    python tools/checkpoint.py --round 3 --level 2    # the same bots against level 2 (the "before")
    python tools/checkpoint.py --all --markdown       # every round (the README's expected-results table)

Every round runs EVERY bot of the chapter, so you see both sides at each level: the bots
the current layers stop, and the ones that still get through (the next round's problem).
"Stopped" means a challenge or a block verdict. The 40 shoppers (tools/population.py with
tools/personas_ch3.py) buy the same drop at the same time, each with a behavior profile:

    blocked      a false positive: the round FAILS on any blocked shopper
    challenged   friction, listed per profile: the round fails above the round's budget

The checkpoint also scores your own recorded traces (tools/traces/*.json with
"source": "browser", from tools/save_trace.py) offline at the round's level, and fails if
one of them would be blocked. Defender cost is reported as the gate's milliseconds
(Server-Timing) and the telemetry each shopper uploaded.

Catching up: the layers are pre-written, so `--catch-up` only installs the round's
defenses/ladder.py and policy.py from solutions/round<N>/.

The drop gets 200 pairs for the checkpoint (the story says 50) so that bots and shoppers
never compete for stock here: who gets the last pair is not this chapter's question.

Needs Playwright: pip install -r requirements-browser.txt && python -m playwright install chromium
"""

import glob
import json
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import labclient  # noqa: E402
import personas_ch3  # noqa: E402,F401  (registers the "behavior_drop" scenario)
from checkpoint_core import LAB, Round, main  # noqa: E402

sys.path.insert(0, LAB)
from defenses.behavior import score_offline  # noqa: E402

CHECKPOINT_STOCK = 200
_reset = labclient.reset
labclient.reset = lambda mode="state", **params: _reset(mode, **dict({"stock": CHECKPOINT_STOCK}, **params))

# name -> (script, the level from which it must be stopped, how many runs must be stopped there)
BOTS = {
    "round1_click_fill": ("attacks/round1_click_fill.py", 1, None),
    "round2_linear_steps": ("attacks/round2_linear_steps.py", 2, None),
    "round3_humanizer": ("attacks/round3_humanizer.py --runs 2", 3, None),
    "round3_humanizer_ease": ("attacks/round3_humanizer.py --ease --runs 2", 3, 1),
    "round4_forge": ("attacks/round4_replay.py --forge", 4, None),
    "round4_replay": ("attacks/round4_replay.py --runs 3", 4, 2),
    "round5_touch_tap": ("attacks/round5_touch_tap.py", 5, None),
    "round5_touch_cdp": ("attacks/round5_touch_tap.py --cdp", 99, None),     # the attacker's answer: never stopped here
}

# Challenges the shoppers may take per round: voice control and the no-JavaScript shopper
# are stopped by design from Level 1 (Sections 3.3 and 3.9); one more is slack for chance.
FRICTION_BUDGET = {0: 0, 1: 3, 2: 3, 3: 3, 4: 3, 5: 3}


def bot_expectations(level):
    """
    `expect` for the bots judged by rate; the 'stopped >= k of n' ones go to extra checks.
    Below its level a bot must get through at least once ("some"): an earlier layer may
    still catch an unlucky run (L2 sometimes challenges a very flat Bezier from Round 3).
    """
    out = {}
    for name, (_, first, must) in BOTS.items():
        if level < first:
            out[name] = "some"
        elif must is None:
            out[name] = "blocked"
    return out


def partial_stops(level):
    def check(board, results, attacks):
        bad = []
        for name, (_, first, must) in BOTS.items():
            if must is None or level < first:
                continue
            out = attacks.get(name) or {}
            stopped = out.get("attempted", 0) - out.get("succeeded", 0)
            if stopped < must:
                bad.append(f"{name}: stopped {stopped}/{out.get('attempted', 0)}, expected >= {must}")
        return (not bad, "; ".join(bad))
    return check


def shoppers(level):
    def check(board, results, attacks):
        by = {}
        for r in results:
            row = by.setdefault(r.get("profile", "?"), {"n": 0, "challenged": 0, "blocked": 0})
            row["n"] += 1
            row["challenged"] += r.get("outcome") == "challenged"
            row["blocked"] += r.get("outcome") == "blocked"
        print("\nshoppers by behavior profile      n  challenged  blocked")
        for name, row in sorted(by.items()):
            print(f"  {name:<30}{row['n']:>3}{row['challenged']:>11}{row['blocked']:>9}")
        for r in results:
            if r.get("outcome") in ("challenged", "blocked"):
                print(f"    {r['outcome']:<10} {r.get('profile')}: score {r.get('score')}  {r.get('signals')}")
        gate = [r["gate_ms"] for r in results if r.get("gate_ms") is not None]
        sizes = [r["telemetry_bytes"] for r in results if r.get("telemetry_bytes") and r.get("profile") in ("mouse", "trackpad", "tremor")]
        if gate:
            print(f"defender cost: gate median {statistics.median(gate):.2f} ms, max {max(gate):.2f} ms on the drop POST")
        if sizes:
            print(f"               telemetry median {statistics.median(sizes) / 1024:.1f} KB per mouse shopper, max {max(sizes) / 1024:.1f} KB")
        challenged = sum(r.get("outcome") == "challenged" for r in results)
        budget = FRICTION_BUDGET[level]
        return (challenged <= budget, f"{challenged} shoppers challenged, budget {budget}")
    return check


def my_traces(level):
    def check(board, results, attacks):
        bad = []
        mine = [p for p in sorted(glob.glob(os.path.join(HERE, "traces", "*.json")))
                if json.load(open(p)).get("source") == "browser"]
        if not mine:
            print("your traces: none yet (reserve a pair in your browser, then python tools/save_trace.py --name <you>)")
        for path in mine:
            score, reasons, verdict = score_offline(json.load(open(path)), level)
            print(f"your trace {os.path.basename(path)}: {verdict} (score {score}) {'; '.join(reasons)}")
            if verdict == "block":
                bad.append(os.path.basename(path))
        return (not bad, "your own trace would be blocked: " + ", ".join(bad))
    return check


def make_round(n, description):
    return Round(level=n, description=description, scenario="behavior_drop",
                 attacks={name: script for name, (script, _, _) in BOTS.items()},
                 expect=bot_expectations(n), bot_success_max=1.0,
                 extra_checks=[partial_stops(n), shoppers(n), my_traces(n)],
                 solutions=("defenses/ladder.py", "defenses/policy.py"))


ROUNDS = {
    0: make_round(0, "instrument: the collector records, nobody is stopped"),
    1: make_round(1, "L1 presence & sanity"),
    2: make_round(2, "L2 kinematics & keystroke dynamics"),
    3: make_round(3, "L3 motor-control realism"),
    4: make_round(4, "L4 layout jitter & replay signatures"),
    5: make_round(5, "L5 touch realism"),
}

if __name__ == "__main__":
    main(ROUNDS)
