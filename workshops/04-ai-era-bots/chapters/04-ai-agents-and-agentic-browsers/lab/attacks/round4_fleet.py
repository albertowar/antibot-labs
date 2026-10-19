"""
Round 4, 🔴 the fleet: many agents, fresh accounts, one machine.

The humanized undeclared agent from Round 2 can buy one unit. The scalper's move is to run it many
times: a fleet of agent sessions, each registering a throwaway account, each reading its own
(synthetic) inbox so it can clear the step-up, all racing for the limited drop.

Round 4's checkout gate (defenses/checkout_gate.py) is what the whole chapter has been building
toward. Against this fleet it does two things:

  step-up    every fresh account with no history is asked to confirm with an emailed code. The fleet
             owns its inboxes, so it passes: friction, not a wall. (A real user's agent would hand
             this back to the human.)
  cap        the per-ACCOUNT cap is useless here (every unit is a new account), but the per-DEVICE cap
             is not: every session runs in the same Chromium on one machine, so they share one
             browser fingerprint. The gate counts units per fingerprint and stops at PER_DEVICE_CAP.

Result at DEFENSE_LEVEL 4: the fleet wins at most the cap instead of every unit. Beating the cap means
a different real device per unit (W2 Ch2, fingerprint stability), a cost the attacker now pays once
per unit. The rented residential exits change nothing: the gate does not
look at the address.

Run (store at the round's level, from lab/):
    python attacks/round4_fleet.py [--sessions 6]
"""

import argparse
import sys

import _common
from agent.act import HumanizedExecutor
from agent.loop import run_agent_session
from labclient import world_pool


def run(sessions=6):
    base = _common.target()
    rng = _common.rng_for("fleet")
    exits = world_pool("residential_proxy_net")[:sessions]
    results = []
    with _common.Cost() as cost, _common.chromium() as browser:
        for i in range(sessions):
            acct = _common.fleet_identity(rng)
            with _common.agent_session(browser, f"bot:fleet:{i:02d}", exits[i]) as (ctx, page):
                ex = HumanizedExecutor(page, base, rng=_common.rng_for(f"fleet-{i}"))
                results.append(run_agent_session(page, base, acct, _common.DROP_SKU, executor=ex, register_first=True,
                                                 mailbox=lambda email: _common.mailbox_code(base, email),
                                                 highlight=False, max_steps=16, label=f"fleet-{i}"))
    return _common.summary("round4_fleet", results, cost)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=6)
    _common.report(run(ap.parse_args().sessions), success_label="drop units won")
    sys.exit(0)
