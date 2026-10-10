"""Round 2 defense (YOUR CODE) — funnel integrity for a limited drop.

The drop has 50 pairs. The generic rate limit does not stop a scalper that paces
itself: attacks/round2_scalper.py grabs the whole drop before a human finishes
typing. Scalper traffic looks like buying, so target the economics instead:
make the checkout funnel behave like a human one, and cap units per identity.

ctx keys:
    view_age_s   : float | None -- seconds since this session viewed the product,
                                   or None if it never did
    bought_by_fp : int          -- pairs this fingerprint has already bought
    fp           : str          -- the client fingerprint

Return BLOCK to refuse, CHALLENGE for friction (queue / CAPTCHA), ALLOW to sell.
`python tools/checkpoint.py --round 2 --catch-up` drops in the reference solution.
"""

from __future__ import annotations

from store import allow, Decision

MIN_FUNNEL_SECONDS = 1.2
PURCHASE_CAP = 1


def evaluate(ctx) -> Decision:
    # TODO (Round 2): add three checks, cheapest first.
    #   1. ctx["view_age_s"] is None            -> block (skipped the funnel)
    #   2. ctx["bought_by_fp"] >= PURCHASE_CAP  -> block (one per customer)
    #   3. ctx["view_age_s"] < MIN_FUNNEL_SECONDS -> challenge (machine speed)
    return allow("sold (no funnel checks wired yet)")
