"""
Round 2, 🔴 the humanized agent — beat the behaviour score the way W2 Ch3 did.

Round 2's defence (defenses/agent_behavior.py) challenges a session that acts
like an agent: teleport clicks, keystroke-free fills, metronome timing,
programmatic scrolls, and injected highlight overlays. The naive undeclared
agent from Round 1 trips all of these and gets challenged.

So the attacker does what W2 Ch3 taught against behavioural detection:
  - swap the stock Executor for HumanizedExecutor: a Bezier cursor path to each
    control and per-character typing (the ghost-cursor recipe)
  - turn the highlight overlays OFF (observe without drawing)
  - jitter the think time between pages so the cadence is not a metronome

None of this is a real hand — it is plausible means with the wrong fine
structure (W2 Ch3's lesson) — but it clears the shape checks this layer can
afford to run, and the agent gets through at DEFENSE_LEVEL 2. The honest cost
to notice: the same humanization is what the "rpa-macro" real user looks like.

Run (store at the round's level, from lab/):
    DEMO_URL=http://127.0.0.1:8404 python attacks/round2_humanized_agent.py
"""

import sys

import _common
from agent.act import HumanizedExecutor
from agent.browser import agent_browser
from agent.loop import run_agent_session


def run(base=None, sessions=5):
    base = base or _common.target()
    accounts = _common.owner_accounts(sessions)
    results = []
    with _common.Cost() as cost:
        for i, acct in enumerate(accounts):
            with agent_browser(user_agent=_common.CHROME_UA) as (ctx, page):
                ctx.set_extra_http_headers({"X-Lab-Actor": "agent-humanized"})
                ex = HumanizedExecutor(page, base, rng=_common.rng_for(f"humanized-{i}"))
                results.append(run_agent_session(page, base, acct, _common.DROP_SKU, executor=ex,
                                                  highlight=False, label=f"humanized-agent-{i}"))
    return _common.summary("round2_humanized_agent", results, cost)


if __name__ == '__main__':
    _common.report(run())
    sys.exit(0)
