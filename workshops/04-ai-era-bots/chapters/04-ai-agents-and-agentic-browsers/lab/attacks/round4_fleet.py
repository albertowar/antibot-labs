"""
Round 4, 🔴 the fleet — many agents, fresh accounts, one machine.

The humanized undeclared agent from Round 2 can buy one unit. The scalper's
move is to run it many times: a fleet of agent sessions, each registering a
throwaway account, each reading its own (synthetic) inbox so it can clear the
human step-up, all racing for the limited drop.

Round 4's checkout gate (defenses/checkout_gate.py) is what the whole chapter
has been building toward. Against this fleet it does two things:

  step-up    every fresh account with no history is asked to confirm with an
             emailed code. The fleet owns its inboxes, so it passes — friction,
             not a wall. (A real user's agent would hand this back to the human.)
  caps       the per-ACCOUNT cap is useless here (every unit is a new account),
             but the per-DEVICE cap is not: all these sessions run in the same
             Chromium on one machine, so they share one fingerprint. The gate
             keys the drop on that fingerprint and lets exactly one unit through.

Result at DEFENSE_LEVEL 4: the fleet's 12 sessions win at most 1–2 units
instead of 12. Beating the device cap means a different real device per unit —
which is W2 Ch4 (fingerprint stability) and the economics of W3 Ch6, i.e. a
cost the attacker now has to pay twelve times over.

Run (store at the round's level, from lab/):
    DEMO_URL=http://127.0.0.1:8404 python attacks/round4_fleet.py
"""

import sys

import _common
from agent.act import HumanizedExecutor
from agent.browser import agent_browser
from agent.loop import run_agent_session


def run(base=None, sessions=12):
    base = base or _common.target()
    rng = _common.rng_for("fleet")
    results = []
    with _common.Cost() as cost:
        for i in range(sessions):
            acct = _common.fleet_identity(rng)
            with agent_browser(user_agent=_common.CHROME_UA) as (ctx, page):
                ctx.set_extra_http_headers({"X-Lab-Actor": "fleet"})
                ex = HumanizedExecutor(page, base, rng=_common.rng_for(f"fleet-{i}"))
                r = run_agent_session(page, base, acct, _common.DROP_SKU, executor=ex, register_first=True,
                                      mailbox=lambda email: _common.mailbox_code(base, email),
                                      highlight=False, max_steps=16, label=f"fleet-{i}")
                results.append(r)
    return _common.summary("round4_fleet", results, cost)


if __name__ == '__main__':
    _common.report(run(), success_label="drop units won")
    sys.exit(0)
