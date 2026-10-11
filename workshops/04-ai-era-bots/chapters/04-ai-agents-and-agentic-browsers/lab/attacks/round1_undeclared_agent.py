"""
Round 1, 🔴 the attack that beats the policy — the SAME agent, undeclared.

The policy in Round 1 only sorts the cooperative from everyone else. An
attacker just doesn't cooperate: the exact same observe→decide→act loop, in a
stock Chromium with a stock Chrome User-Agent and no Signature-Agent header.
To the store it is a logged-in customer in a real browser. Nothing in the
request says "agent", so the policy has nothing to act on, and the checkout
goes through.

At DEFENSE_LEVEL 1 this buys. That is the whole lesson of Round 1: declaration
is a convenience for honest operators, not a control. Round 2 stops this agent
by how it ACTS, not by what it calls itself.

Run (store at the round's level, from lab/):
    DEMO_URL=http://127.0.0.1:8404 python attacks/round1_undeclared_agent.py
"""

import sys

import _common
from agent.browser import agent_browser
from agent.loop import run_agent_session


def run(base=None, sessions=5, actor="agent"):
    base = base or _common.target()
    accounts = _common.owner_accounts(sessions)
    results = []
    with _common.Cost() as cost:
        for i, acct in enumerate(accounts):
            with agent_browser(user_agent=_common.CHROME_UA) as (ctx, page):
                ctx.set_extra_http_headers({"X-Lab-Actor": actor})
                results.append(run_agent_session(page, base, acct, _common.DROP_SKU,
                                                  highlight=True, label=f"undeclared-agent-{i}"))
    return _common.summary("round1_undeclared_agent", results, cost)


if __name__ == '__main__':
    _common.report(run())
    sys.exit(0)
