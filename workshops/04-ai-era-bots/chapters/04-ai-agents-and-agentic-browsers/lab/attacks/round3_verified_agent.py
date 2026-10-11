"""
Round 3, 🔵 the happy path — a verified agent the store chooses to trust.

This is not an attack; it is the outcome the identity layer is meant to
enable. The lab operator agents.lab-provider.test holds an Ed25519 key, the
store trusts that operator (defenses/trusted_operators.json), and the agent
signs every request with it (Web Bot Auth, RFC 9421). The store verifies the
signature, classifies the session as a verified agent, and — at DEFENSE_LEVEL
3 — lets it check out, because now the store knows who stands behind it.

It proves the defence does not just block: a cooperative, cryptographically
identified operator gets a smoother path than the undeclared agent, not a
worse one. At DEFENSE_LEVEL 4 this same agent also needs a mandate (Round 4);
here it demonstrates verification alone.

Run (store at the round's level, from lab/):
    DEMO_URL=http://127.0.0.1:8404 python attacks/round3_verified_agent.py
"""

import os
import sys

import _common
from agent.browser import agent_browser
from agent.identity import install_signer
from agent.loop import run_agent_session

sys.path.insert(0, os.path.join(_common.LAB_DIR, "defenses"))
import httpsig  # noqa: E402

OPERATOR = "agents.lab-provider.test"
KEY_PATH = os.path.join(_common.LAB_DIR, "data", "keys", "lab-provider.pem")


def run(base=None, sessions=5):
    base = base or _common.target()
    if not os.path.exists(KEY_PATH):
        sys.exit("No operator key. Run: python tools/make_keys.py")
    key = httpsig.load_private_key(KEY_PATH)
    accounts = _common.owner_accounts(sessions)
    results = []
    with _common.Cost() as cost:
        for i, acct in enumerate(accounts):
            with agent_browser(user_agent=_common.LAB_AGENT_UA) as (ctx, page):
                ctx.set_extra_http_headers({"X-Lab-Actor": "agent-verified"})
                install_signer(ctx, _common.authority(base), key, OPERATOR)
                results.append(run_agent_session(page, base, acct, _common.DROP_SKU,
                                                  label=f"verified-agent-{i}"))
    return _common.summary("round3_verified_agent", results, cost)


if __name__ == '__main__':
    _common.report(run())
    sys.exit(0)
