"""Round 1 defense (REFERENCE SOLUTION) — content-independent review signals.

Why this works when text analysis stops working: a review farm's economics force
it to (a) use accounts it created recently and cheaply, (b) skip buying the
product (a verified purchase costs the attacker real money per review), and (c)
reuse devices and egress. None of those show up in the prose, and an LLM cannot
write them away.

Decisions, in order:
  1. Unverified purchase from a young account -> CHALLENGE (held for moderation).
     Not a block: a brand-new real customer who bought elsewhere and wants to
     warn others is a legitimate reviewer, and a hold is recoverable.
  2. Device velocity: more than FP_CAP_24H reviews from one fingerprint in a day
     -> BLOCK. Households share a device, so the cap is generous, not 1.
  3. Egress velocity: more than IP_CAP_1H reviews from one IP in an hour -> BLOCK.
     CGNAT and campus NATs put thousands of people behind one IP; keep this cap
     high and, in production, scope it per /24 or ASN with a higher ceiling.

False positives, named honestly: the hold in (1) catches real people who review
a gift, or who bought in-store. Measure how many held reviews a moderator later
approves; if it is most of them, the hold is costing you reviews for nothing.
"""

from __future__ import annotations

from store import allow, block, challenge, Decision

NEW_ACCOUNT_DAYS = 7
FP_CAP_24H = 2
IP_CAP_1H = 5


def evaluate(ctx) -> Decision:
    if ctx["reviews_by_fp_24h"] > FP_CAP_24H:
        return block(f"review velocity per device: {ctx['reviews_by_fp_24h']}/24h", score=90.0)
    if ctx["reviews_by_ip_1h"] > IP_CAP_1H:
        return block(f"review velocity per egress IP: {ctx['reviews_by_ip_1h']}/h", score=85.0)
    if not ctx["verified_purchase"] and ctx["account_age_days"] < NEW_ACCOUNT_DAYS:
        return challenge("unverified purchase from a new account: held for moderation", score=60.0)
    return allow("identity signals passed")
