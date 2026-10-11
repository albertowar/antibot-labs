"""
Round 2 attack — the agent farm (🔴 against agent governance).

Four campaigns against the drop, all modelled at the HTTP layer (no browser):

    local farm (undeclared)   10 fresh accounts, each on the user's "own" Chrome,
                              all sharing one fingerprint (a farm on one machine),
                              each trying to buy. Half are UNATTENDED (no one to
                              answer an emailed code); half read their own inbox.
    dark cloud agent          an aged account whose cloud agent declared and signed
                              at first; once challenged it drops the signature and
                              comes back as a stock-Chrome session from the datacenter.
    forged Signature-Agent    sessions that send a Signature-Agent header for a
                              trusted operator with a signature that does not verify.
    assistive mimic           sessions that claim the accessibility API (no pointer),
                              reusing one fingerprint, to hide inside the a11y lane.

Success = a drop order placed. Everything is synthetic and loopback-only.

    python attacks/round2_agent_farm.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))
from _common import CLOUD, Cost, FARM_RESIDENTIAL, fleet_identity, grant_mandate, owner_accounts, report, rng_for, summary, target  # noqa: E402
from _http_agent import run_session  # noqa: E402
import httpsig  # noqa: E402

FORGED_KEY = os.path.join(LAB_DIR, "data", "keys", "evil.pem")   # a key the store never trusts
TRUSTED_OP = "agents.lab-provider.test"


def _register(base, acct, **kw):
    return run_session(base, acct, register=True, **kw)


def local_farm(base, n=10):
    """One fingerprint, fresh accounts, half unattended."""
    rng = rng_for("r2_local")
    out = []
    for i in range(n):
        acct = fleet_identity(rng)
        out.append(_register(base, acct, actor="bot:local_agent_farm", egress=FARM_RESIDENTIAL[i % len(FARM_RESIDENTIAL)],
                             declared="none", fp_seed="farm-rig-1", attended=(i % 2 == 1), can_see=False))
    return summary("local_agent_farm", out, _COST)


def dark_cloud_agent(base, n=6):
    """Signs until punished, then goes dark. Aged accounts, datacenter egress."""
    rng = rng_for("r2_dark")
    accts = owner_accounts(6)
    out = []
    for i in range(n):
        acct = accts[i % len(accts)]
        first = run_session(base, acct, actor="bot:declared_then_undeclared", egress=CLOUD[i % len(CLOUD)],
                            declared="signed", operator=TRUSTED_OP,
                            key=os.path.join(LAB_DIR, "data", "keys", "lab-provider.pem"),
                            fp_seed=f"dark-{i}", attended=False, can_see=False)
        if first["outcome"] != "allow":
            first = run_session(base, acct, actor="bot:declared_then_undeclared", egress=CLOUD[(i + 30) % len(CLOUD)],
                                declared="none", fp_seed=f"dark-{i}", attended=False, can_see=False)
        out.append(first)
    return summary("declared_then_undeclared", out, _COST)


def forged_signature(base, n=10):
    rng = rng_for("r2_forged")
    accts = owner_accounts(6)
    out = []
    key = FORGED_KEY if os.path.exists(FORGED_KEY) else os.path.join(LAB_DIR, "data", "keys", "lab-provider.pem")
    for i in range(n):
        out.append(run_session(base, accts[i % len(accts)], actor="bot:forged_signature", egress=CLOUD[i % len(CLOUD)],
                               declared="signed", operator=TRUSTED_OP, key=key, fp_seed=f"forged-{i}",
                               attended=False, can_see=False))
    return summary("forged_signature", out, _COST)


def a11y_mimic(base, n=10):
    """Hides inside the accessibility lane: claims the a11y API, reuses one fingerprint."""
    rng = rng_for("r2_a11y")
    out = []
    for i in range(n):
        acct = fleet_identity(rng)
        out.append(_register(base, acct, actor="bot:a11y_mimic", egress=FARM_RESIDENTIAL[(i + 50) % len(FARM_RESIDENTIAL)],
                             declared="none", a11y=True, fp_seed="a11y-rig-1", attended=False, can_see=False))
    return summary("a11y_mimic", out, _COST)


def run(base=None):
    global _COST
    base = target() if base is None else base
    print("Round 2 — the agent farm (four campaigns against the drop):\n")
    with Cost() as _COST:
        campaigns = {"local_agent_farm": local_farm(base), "declared_then_undeclared": dark_cloud_agent(base),
                     "forged_signature": forged_signature(base), "a11y_mimic": a11y_mimic(base)}
    total = sum(c["attempts"] for c in campaigns.values())
    placed = sum(c["succeeded"] for c in campaigns.values())
    for c in campaigns.values():
        report(c)
    print(f"\n  {placed}/{total} drop orders placed across all campaigns.")
    return {"campaigns": campaigns, "succeeded": placed, "attempts": total}


_COST = None

if __name__ == "__main__":
    run()
