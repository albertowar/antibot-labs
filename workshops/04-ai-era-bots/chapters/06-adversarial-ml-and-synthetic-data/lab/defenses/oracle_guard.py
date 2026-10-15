"""
Round 1 defense: deny the extraction oracle (reference solution)

A per-address query budget. A clone needs many labelled queries, and a cheap extractor sends them from a
handful of boxes. Count the purchase attempts from each exit address in the recent window; once an address
is over its budget, stop answering truthfully and return a CONSTANT refusal. A constant answer carries no
information, so the extra probes teach the clone nothing. Worse for the attacker, they teach it that
configs the model really allows are refused, so the clone's idea of the allowed region shrinks.

The check runs BEFORE the model (defenses/ladder.py), for two reasons: a probe over its budget never costs a
model evaluation, and its refusal is identical whatever the model thought. The answer is a hard `block`
verdict, so the store refuses the purchase before any order is written.

Who pays, and what it does not stop:
  - Shared addresses. A carrier-grade NAT puts dozens of real phones behind one address, and an office or a
    campus puts hundreds of people behind four; a flat budget would refuse the busiest of them on a drop day.
    Addresses on a mobile or corporate network get NAT_FACTOR times the budget (netinfo reads the kind of
    network from the feeds). An attacker who buys exits there inherits the allowance, and mobile proxies are
    the most expensive kind.
  - Rotation. The budget is per address. An extractor that rotates through every exit its provider sells
    spreads the same probes thin and never trips it (attacks/round1_extract.py --patient). The guard raises
    the attacker's cost and slows the lazy one; it does not make the oracle safe. The model has to survive
    being copied: Round 2.

Bonus (not required): add randomized response at the boundary. Within a small band of the threshold, flip
the verdict with probability FLIP_P, keyed deterministically on the session id so a real customer gets a
stable answer. It blunts probing right at the decision line, at the price of refusing or admitting a few
sessions at random.
"""

from . import models, netinfo, store
from .pipeline import Check, Signal, Verdict

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
    if n > budget(ctx):
        ctx.note(oracle_guard="constant")
        return Verdict(action="block", score=100, signals=(Signal("oracle_guard", "over_budget", 0, f"{n} attempts"),))
    return None


CHECK = Check("oracle_guard", _check, phases=("action:drop_buy",))
