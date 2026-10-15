"""
Round 3, 🔵 the happy path: a verified agent the store chooses to trust.

This is not an attack; it is the outcome the identity layer is meant to enable. The lab operator
agents.lab-provider.test holds an Ed25519 key, publishes the public half in its key directory, the
store trusts that operator (policy.TRUSTED_AGENTS), and the agent signs every request with it (Web
Bot Auth, RFC 9421). The store verifies the signature, classifies the session as a verified agent,
and at DEFENSE_LEVEL 3 lets it buy, because now the store knows who stands behind it.

It proves the defense does not just block: a cooperative, cryptographically identified operator gets
a smoother path than the undeclared agent, not a worse one (no behavior score, no step-up). At
DEFENSE_LEVEL 4 this same agent also needs a mandate (Round 4); here it demonstrates verification
alone. Its actors are labelled `legit:`.

Run (store at the round's level, from lab/):
    python attacks/round3_verified_agent.py [--sessions 4]
"""

import argparse
import sys

import _common
from agent.identity import install_signer
from agent.loop import run_agent_session


def run(sessions=4):
    base = _common.target()
    signer = _common.Signer(_common.OPERATOR)
    accounts = _common.owner_accounts(sessions, start=40)
    ips = _common.home_ips(sessions, start=40)
    results = []
    with _common.Cost() as cost, _common.chromium() as browser:
        for i, (acct, ip) in enumerate(zip(accounts, ips)):
            with _common.agent_session(browser, f"legit:verified_agent:{i:02d}", ip, _common.LAB_AGENT_UA) as (ctx, page):
                install_signer(ctx, signer)
                results.append(run_agent_session(page, base, acct, _common.DROP_SKU, label=f"verified-agent-{i}"))
    return _common.summary("round3_verified_agent", results, cost)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=4)
    _common.report(run(ap.parse_args().sessions))
    sys.exit(0)
