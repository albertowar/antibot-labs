"""Round 2 defense (REFERENCE SOLUTION) — funnel integrity for a limited drop.

Economic chokepoint: scarce inventory. The scalper's edge is speed and parallelism
through the page->cart->checkout funnel, and buying many units. Its traffic looks
like buying, so we do not try to "block a bot" — we make the funnel behave like a
human one and cap units per identity.

Three signals, each a scalper tell that costs a real shopper nothing:
  1. no prior product view in this session   -> checkout skipped the funnel (BLOCK)
  2. view-to-checkout faster than a human     -> machine-speed funnel   (CHALLENGE)
  3. this fingerprint already bought a pair    -> one-per-customer cap    (BLOCK)

False positive, named honestly: a decisive human on a fast connection can clear the
funnel quickly; the dwell gate is set below realistic human speed (1.2 s) and sends
them to a CHALLENGE, not a block, so friction is the worst case. Shared-NAT or
family devices can collide on a coarse fingerprint — bind the cap to the account
too, not the fingerprint alone, before shipping.
"""

from __future__ import annotations

from store import allow, block, challenge, Decision

MIN_FUNNEL_SECONDS = 1.2   # view -> checkout faster than this is machine speed
PURCHASE_CAP = 1           # pairs per fingerprint for this drop


def evaluate(ctx) -> Decision:
    if ctx["view_age_s"] is None:
        return block("checkout with no product view this session", score=100.0)
    if ctx["bought_by_fp"] >= PURCHASE_CAP:
        return block(f"fingerprint already bought {ctx['bought_by_fp']}", score=100.0)
    if ctx["view_age_s"] < MIN_FUNNEL_SECONDS:
        return challenge(f"funnel in {ctx['view_age_s']:.2f}s < {MIN_FUNNEL_SECONDS}s", score=70.0)
    return allow("human-paced single purchase")
