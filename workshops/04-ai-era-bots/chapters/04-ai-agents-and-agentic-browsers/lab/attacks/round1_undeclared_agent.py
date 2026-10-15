"""
Round 1, 🔴 the attack that beats the policy: the SAME agent, undeclared.

The policy in Round 1 only sorts the cooperative from everyone else. An attacker just doesn't
cooperate: the exact same observe -> decide -> act loop, in a stock Chromium with a stock Chrome
User-Agent and no Signature-Agent header. To the store it is a signed-in customer in a real browser.
Nothing in the request says "agent", so the policy has nothing to act on, and the purchase goes through.

At DEFENSE_LEVEL 1 this buys. That is the whole lesson of Round 1: declaration is a convenience for
honest operators, not a control. Round 2 stops this agent by how it ACTS, not by what it calls itself:
its fills have no keystrokes, its clicks have no pointer path, its think time is a metronome, and it
draws highlight boxes over the page.

Run (store at the round's level, from lab/):
    python attacks/round1_undeclared_agent.py [--sessions 4]
"""

import argparse
import sys

import _common
from agent.loop import run_agent_session


def run(sessions=4):
    accounts = _common.owner_accounts(sessions, start=0)
    ips = _common.home_ips(sessions, start=0)
    results = []
    with _common.Cost() as cost, _common.chromium() as browser:
        for i, (acct, ip) in enumerate(zip(accounts, ips)):
            with _common.agent_session(browser, f"bot:undeclared_agent:{i:02d}", ip) as (ctx, page):
                results.append(run_agent_session(page, _common.target(), acct, _common.DROP_SKU,
                                                 highlight=True, label=f"undeclared-agent-{i}"))
    return _common.summary("round1_undeclared_agent", results, cost)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=4)
    _common.report(run(ap.parse_args().sessions))
    sys.exit(0)
