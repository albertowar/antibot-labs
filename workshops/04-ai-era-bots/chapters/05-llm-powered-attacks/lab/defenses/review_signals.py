"""Round 1 defense (YOUR CODE) — content-independent review signals.

The LLM review farm writes 40 unique, on-topic reviews, so content_heuristics.py
passes every one of them. What the farm cannot fake cheaply is *who* is writing:
the accounts were created this morning, none of them bought the product, and
forty of them share a handful of devices and egress IPs. Those are the signals.

ctx keys:
    account_age_days   : float  how old the reviewing account is
    verified_purchase  : bool   did this account buy this SKU?
    reviews_by_fp_24h  : int    reviews from this device fingerprint today (incl. this one)
    reviews_by_ip_1h   : int    reviews from this egress IP this hour (incl. this one)
    net_type           : str    residential / datacenter / unknown

Return CHALLENGE to hold a review for moderation (it is not published, so it does
not count as attacker success), BLOCK to refuse it outright. A real reviewer who
is held is friction; one who is blocked is a false positive.
`python tools/checkpoint.py --round 1 --catch-up` drops in the reference solution.
"""

from __future__ import annotations

from store import allow, Decision

NEW_ACCOUNT_DAYS = 7
FP_CAP_24H = 2
IP_CAP_1H = 5


def evaluate(ctx) -> Decision:
    # TODO (Round 1):
    #   1. unverified purchase AND account younger than NEW_ACCOUNT_DAYS -> challenge (hold)
    #   2. reviews_by_fp_24h > FP_CAP_24H -> block   (one device, many "customers")
    #   3. reviews_by_ip_1h  > IP_CAP_1H  -> block   (one egress, many "customers")
    return allow("no identity signals wired yet")
