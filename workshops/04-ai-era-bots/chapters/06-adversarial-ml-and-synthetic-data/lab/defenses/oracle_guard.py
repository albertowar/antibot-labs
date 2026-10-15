"""
Round 1 defense: deny the extraction oracle  [YOUR FILE]

Every purchase attempt the store answers is a free labelled query against your model: allowed or
refused. attacks/round1_extract.py milks that oracle to train a clone (the surrogate), then uses
the clone to craft sessions the real model admits. The defense is a per-address query budget: a
clone needs many labelled queries, and a cheap extractor sends them from a handful of boxes. Once
an address is over its budget, stop answering truthfully and return a CONSTANT refusal — a
constant answer carries no information, and the probes it does get teach the clone that allowed
configs are refused, so its idea of the allowed region shrinks.

The check runs BEFORE the model (defenses/ladder.py): a probe over budget never costs a model
evaluation, and its refusal is identical whatever the model thought.

Who pays, and what it does not stop:
  - Shared addresses. Carrier NAT and office egress put many real people behind one address; a
    flat budget refuses the busiest of them on a drop day. Give mobile and corporate networks
    NAT_FACTOR times the budget (netinfo reads the kind of network from the feeds). An attacker
    who buys exits there inherits the allowance — and those proxies cost the most.
  - Rotation. The budget is per address; an extractor that rotates exits spreads its probes thin
    (attacks/round1_extract.py --patient). The guard raises cost; it does not make the oracle
    safe. The model has to survive being copied: Round 2.

This is the STUB. It keeps the bookkeeping (every attempt is counted and noted, so you can watch
an extraction run in /lab/decisions) but refuses nobody: the oracle answers every probe.

TODO (Round 1): implement the refusal in _check().
  Compare attempts(ctx) to budget(ctx); over it, note oracle_guard="constant" and return a hard
  block: Verdict(action="block", score=100, signals=(Signal("oracle_guard", "over_budget", 0,
  f"{n} attempts"),)). budget(ctx) multiplies BUDGET by NAT_FACTOR when
  netinfo.lookup(ctx.ip)["asn_type"] is "mobile" or "corporate".
Then run the checkpoint and watch the cheap extractor starve while the patient one still gets
through.

Fell behind? python tools/checkpoint.py --round 1 --catch-up
"""

from . import models, netinfo, store
from .pipeline import Check, Signal, Verdict  # noqa: F401  (Signal and Verdict are for your TODO)

WINDOW_S = 3600          # virtual seconds: models.time_scale() real seconds per virtual second
BUDGET = 6               # purchase attempts per address per window before the oracle goes constant
NAT_FACTOR = 8           # carrier or office NAT: many people, one address


def attempts(ctx):
    """Record this purchase attempt and return how many the address has made in the window (including it)."""
    window = max(1, round(WINDOW_S * models.time_scale()))     # real seconds (Redis wants an integer)
    return store.Counters(ctx.redis).hit("oracle", ctx.ip, window=window)


def budget(ctx):
    """The attempts one address may make per window. Carriers and offices share an address among many people."""
    kind = netinfo.lookup(ctx.ip)["asn_type"]
    return BUDGET * NAT_FACTOR if kind in ("mobile", "corporate") else BUDGET


def _check(ctx):
    n = attempts(ctx)
    ctx.note(oracle_attempts=n)
    # TODO (Round 1): over budget(ctx), answer with the constant refusal (see the module docstring).
    return None


CHECK = Check("oracle_guard", _check, phases=("action:drop_buy",))
