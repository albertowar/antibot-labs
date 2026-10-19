"""
Round 2 attack — the agent farm (🔴 against agent governance).

Four campaigns against the drop, all modelled at the HTTP layer (no browser):

    local farm (undeclared)   10 fresh accounts, each on the user's "own" Chrome,
                              all sharing one fingerprint (a farm on one machine),
                              each trying to buy. Half are UNATTENDED (no one to
                              answer an emailed code); half read their own inbox.
    dark cloud agent          an aged account whose cloud agent signs correctly —
                              but from its OWN origin (attacker.example), which the
                              store does not trust: a valid signature is not
                              entitlement. Once challenged it drops the signature
                              and comes back as a stock-Chrome datacenter session.
    forged Signature-Agent    sessions that claim a TRUSTED operator
                              (agents.lab-provider.test) but sign with the
                              attacker's key: the signature does not verify against
                              the operator's published directory (W4 Ch2's forgery).
    assistive mimic           sessions that claim the accessibility API (no pointer),
                              reusing one fingerprint, to hide inside the a11y lane.

Success = a drop order placed. Everything is synthetic and loopback-only.

    python attacks/round2_agent_farm.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from _common import (CLOUD, Cost, FARM_RESIDENTIAL, fleet_identity, owner_accounts,  # noqa: E402
                     report, rng_for, summary, target)
from _http_agent import run_session  # noqa: E402

TRUSTED_OP = "agents.lab-provider.test"
ATTACKER_OP = "attacker.example"            # an origin that publishes a key the store never trusts


def _register(base, acct, **kw):
    return run_session(base, acct, register=True, **kw)


def local_farm(base, n=10):
    """One fingerprint, fresh accounts, half unattended."""
    rng = rng_for("r2_local")
    out = []
    for i in range(n):
        acct = fleet_identity(rng)
        out.append(_register(base, acct, actor="bot:local_agent_farm",
                             egress=FARM_RESIDENTIAL[i % len(FARM_RESIDENTIAL)],
                             declared="none", fp_seed="farm-rig-1", attended=(i % 2 == 1), can_see=False))
    return summary("local_agent_farm", out, _COST)


def dark_cloud_agent(base, n=6):
    """Signs correctly from its own untrusted origin; when that earns nothing, goes dark."""
    accts = owner_accounts(6)
    out = []
    for i in range(n):
        acct = accts[i % len(accts)]
        first = run_session(base, acct, actor="bot:declared_then_undeclared", egress=CLOUD[i % len(CLOUD)],
                            declared="signed", operator=ATTACKER_OP, sign=True, key_origin=ATTACKER_OP,
                            fp_seed=f"dark-{i}", attended=False, can_see=False)
        if first["outcome"] != "allow":
            first = run_session(base, acct, actor="bot:declared_then_undeclared",
                                egress=CLOUD[(i + 30) % len(CLOUD)], declared="none",
                                fp_seed=f"dark-{i}", attended=False, can_see=False)
        out.append(first)
    return summary("declared_then_undeclared", out, _COST)


def forged_signature(base, n=10):
    """Claims a trusted operator but signs with the attacker's key: the signature is invalid."""
    accts = owner_accounts(6)
    out = []
    for i in range(n):
        out.append(run_session(base, accts[i % len(accts)], actor="bot:forged_signature",
                               egress=CLOUD[i % len(CLOUD)], declared="signed", operator=TRUSTED_OP,
                               sign=True, key_origin=ATTACKER_OP, fp_seed=f"forged-{i}",
                               attended=False, can_see=False))
    return summary("forged_signature", out, _COST)


def a11y_mimic(base, n=10):
    """Hides inside the accessibility lane: claims the a11y API, reuses one fingerprint."""
    rng = rng_for("r2_a11y")
    out = []
    for i in range(n):
        acct = fleet_identity(rng)
        out.append(_register(base, acct, actor="bot:a11y_mimic",
                             egress=FARM_RESIDENTIAL[(i + 50) % len(FARM_RESIDENTIAL)],
                             declared="none", a11y=True, fp_seed="a11y-rig-1", attended=False, can_see=False))
    return summary("a11y_mimic", out, _COST)


def run(base=None):
    global _COST
    base = target() if base is None else base
    print("Round 2 — the agent farm (four campaigns against the drop):\n")
    with Cost() as _COST:
        campaigns = {"local_agent_farm": local_farm(base), "declared_then_undeclared": dark_cloud_agent(base),
                     "forged_signature": forged_signature(base), "a11y_mimic": a11y_mimic(base)}
    total = sum(c["attempted"] for c in campaigns.values())
    placed = sum(c["succeeded"] for c in campaigns.values())
    for c in campaigns.values():
        report(c)
    print(f"\n  {placed}/{total} drop orders placed across all campaigns.")
    return {"campaigns": campaigns, "succeeded": placed, "attempted": total}


_COST = None

if __name__ == "__main__":
    run()
