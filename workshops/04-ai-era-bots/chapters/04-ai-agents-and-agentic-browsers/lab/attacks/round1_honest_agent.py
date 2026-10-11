"""
Round 1, 🔴 the honest agent — a user-directed agent that plays by the rules.

This is the cooperative case the store wants to support: a person told their
agent "buy me the Lab Runner 9". The agent identifies itself in the
User-Agent (a ChatGPT-User-style token pointing at its operator), browses the
catalogue, adds the item, and tries to check out.

At DEFENSE_LEVEL 0 it buys. At DEFENSE_LEVEL 1 the store's agent policy
(defenses/agent_policy.py) lets it browse and add to cart, then refuses the
checkout with a machine-readable hint — because an honest agent should not be
able to transact until it is verified and mandated (Rounds 3–4). The agent
reads the refusal and stops, exactly as a well-behaved agent should.

This script shows the policy doing its job. round1_undeclared_agent.py shows
why the policy is not enough on its own.

Run (store at the round's level, from lab/):
    DEMO_URL=http://127.0.0.1:8404 python attacks/round1_honest_agent.py
"""

import sys

import _common
from agent.browser import agent_browser
from agent.loop import run_agent_session


def run(base=None, sessions=5):
    base = base or _common.target()
    accounts = _common.owner_accounts(sessions)
    results = []
    with _common.Cost() as cost:
        for i, acct in enumerate(accounts):
            with agent_browser(user_agent=_common.LAB_AGENT_UA) as (ctx, page):
                ctx.set_extra_http_headers({"X-Lab-Actor": "agent-honest"})
                results.append(run_agent_session(page, base, acct, _common.DROP_SKU,
                                                  label=f"honest-agent-{i}"))
    return _common.summary("round1_honest_agent", results, cost)


if __name__ == '__main__':
    _common.report(run())
    sys.exit(0)
