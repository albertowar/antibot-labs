"""
Round 2, 🔴 the humanized agent: beat the behaviour score the way W2 Ch3 did.

Round 2's defense (defenses/agent_behavior.py) challenges a session that acts like an agent: teleport
clicks, keystroke-free fills, metronome timing, programmatic scrolls, and injected highlight overlays.
The naive undeclared agent from Round 1 trips all of these and meets the step-up, which it cannot
answer: the code goes to its user's inbox, not to the agent.

So the attacker does what W2 Ch3 taught against behavioural detection:
  - swap the stock Executor for HumanizedExecutor: a Bezier cursor path to each control, wheel ticks
    instead of scrollIntoView(), and per-character typing (the ghost-cursor recipe)
  - turn the highlight overlays OFF (observe without drawing)
  - jitter the think time between pages so the cadence is not a metronome

None of this is a real hand. It is plausible means with the wrong fine structure (W2 Ch3's lesson),
but it clears the shape checks this layer can afford to run, and the agent buys at DEFENSE_LEVEL 2.
The honest cost to notice: the same humanization is what the "rpa_macro" real user looks like from
the other side.

Run (store at the round's level, from lab/):
    python attacks/round2_humanized_agent.py [--sessions 4]
"""

import argparse
import sys

import _common
from agent.act import HumanizedExecutor
from agent.loop import run_agent_session


def run(sessions=4):
    base = _common.target()
    accounts = _common.owner_accounts(sessions, start=20)
    ips = _common.home_ips(sessions, start=20)
    results = []
    with _common.Cost() as cost, _common.chromium() as browser:
        for i, (acct, ip) in enumerate(zip(accounts, ips)):
            with _common.agent_session(browser, f"bot:humanized_agent:{i:02d}", ip) as (ctx, page):
                ex = HumanizedExecutor(page, base, rng=_common.rng_for(f"humanized-{i}"))
                results.append(run_agent_session(page, base, acct, _common.DROP_SKU, executor=ex,
                                                 highlight=False, label=f"humanized-agent-{i}"))
    return _common.summary("round2_humanized_agent", results, cost)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=4)
    _common.report(run(ap.parse_args().sessions))
    sys.exit(0)
