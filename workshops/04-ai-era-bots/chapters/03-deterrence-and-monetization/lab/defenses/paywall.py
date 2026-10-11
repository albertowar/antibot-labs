"""Round 4 defense [STUDENT FILE] — pay-per-crawl over HTTP 402.

A clone of the Cloudflare pay-per-crawl exchange (2025-26), the first deployed
protocol that turns "no" into "yes, for a price":

  reactive   crawler GET /product/x                 -> 402, `crawler-price: USD 0.01`
             crawler GET /product/x + `crawler-exact-price: USD 0.01`
                                                     -> 200, `crawler-charged: USD 0.01`
  proactive  crawler GET /product/x + `crawler-max-price: USD 0.05`
                                                     -> 200, charged the configured
                                                        price if <= max, else 402

Only one price-declaration header per request; anything malformed is a 402. A
billing event exists only for a *verified* identity (bot_identity.py): the
ledger is keyed on the operator the signature names. That is why Round 2's
enforcement sits in front: an unverified "LabTrainBot" is refused, never billed.

TODO 1 is evaluate(). TODO 2 is the lesson most teams learn in production: the
paywall was wired on the HTML pages and the catalogue leaked for free through the
JSON API, search and the sitemap. Every content carrier must sit behind the same
policy. Fell behind? python tools/checkpoint.py --round 4 --catch-up

What this never reaches: the stealth crawler of Round 3. Monetization governs
the honest; deterrence and detection handle the rest. And the honest can still
walk away: most 402s in the wild are never paid.
"""

from __future__ import annotations

from store import allow, block, charged, paywall, Decision

PAYWALL = {
    "enabled": True,
    "price_usd": 0.01,
    "purposes": ("ai-train", "ai-input"),   # search stays free: we want the referrals
}

# TODO 2 (Round 4): every carrier of catalogue data, not just the pages a human
# sees. Which other routes serve the same products? Add them here.
PAID_PATHS = ("/catalog", "/product/")


def applies(path: str) -> bool:
    return any(path.startswith(p) for p in PAID_PATHS)


def _parse(value):
    """'USD 0.01' -> 0.01, or None when absent/malformed."""
    if not value:
        return None
    parts = value.strip().split()
    if len(parts) != 2 or parts[0].upper() != "USD":
        return None
    try:
        return round(float(parts[1]), 4)
    except ValueError:
        return None


def evaluate(ctx) -> Decision:
    """TODO 1 (Round 4): the 402 exchange. ctx has "identity", "price" (configured
    USD price), "exact" and "max" (the raw crawler-exact-price / crawler-max-price
    header values, or None).
      * unverified identity                  -> block("cannot bill an unverified crawler", score=80.0)
      * both headers present                 -> paywall("only one price declaration header allowed", price)
      * a header present but malformed       -> paywall("malformed price declaration", price)
      * exact == price                       -> charged(..., price); any other exact -> paywall(..., price)
      * max >= price                         -> charged(..., price); lower -> paywall(..., price)
      * no header                            -> paywall("price discovery", price)
    _parse() turns "USD 0.01" into 0.01 (None when malformed).
    Until then every crawler gets the content for free.
    """
    return allow("TODO (Round 4): no paywall yet")
