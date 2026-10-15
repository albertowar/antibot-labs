"""
Round 1, 🔵 the honest agent: a user-directed agent that plays by the rules.

This is the cooperative case the store wants to support: a person told their agent "buy me the Lab
Runner 9". The agent identifies itself in the User-Agent (a LabAgent token pointing at its operator),
reads the catalogue, opens the drop and tries to buy.

At DEFENSE_LEVEL 0 it buys. At DEFENSE_LEVEL 1 the store's agent policy (defenses/agent_policy.py)
lets it browse and refuses the purchase, because an honest agent should not be able to transact until
it is verified and mandated (Rounds 3-4). The agent reads the refusal and stops, exactly as a
well-behaved agent should.

This script shows the policy doing its job. round1_undeclared_agent.py shows why the policy is not
enough on its own. (Its actors are labelled `legit:`: a refusal here is not a bot stopped.)

Run (store at the round's level, from lab/):
    python attacks/round1_honest_agent.py [--sessions 4]
"""

import argparse
import sys

import _common
from agent.loop import run_agent_session


def run(sessions=4):
    accounts = _common.owner_accounts(sessions, start=10)
    ips = _common.home_ips(sessions, start=10)
    results = []
    with _common.Cost() as cost, _common.chromium() as browser:
        for i, (acct, ip) in enumerate(zip(accounts, ips)):
            with _common.agent_session(browser, f"legit:honest_agent:{i:02d}", ip, _common.LAB_AGENT_UA) as (ctx, page):
                results.append(run_agent_session(page, _common.target(), acct, _common.DROP_SKU,
                                                 label=f"honest-agent-{i}"))
    return _common.summary("round1_honest_agent", results, cost)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=4)
    _common.report(run(ap.parse_args().sessions))
    sys.exit(0)
