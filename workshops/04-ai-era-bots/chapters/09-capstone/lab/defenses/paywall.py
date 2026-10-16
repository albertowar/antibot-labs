"""Round 4 defense (REFERENCE SOLUTION) — pay-per-crawl over HTTP 402.

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

The lesson most teams learn in production: wire the paywall on the HTML pages only and
the catalogue leaks for free through the JSON API, search
and the sitemap. Every content carrier must sit behind the same policy.

What this never reaches: the stealth crawler of Round 3. Monetization governs
the honest; deterrence and detection handle the rest. And the honest can still
walk away: most 402s in the wild are never paid.
"""

from __future__ import annotations

from .decision import allow, block, charged, paywall, Decision

PAYWALL = {
    "enabled": True,
    "price_usd": 0.01,
    "purposes": ("ai-train", "ai-input"),   # search stays free: we want the referrals
}

# Every carrier of catalogue data, not just the pages a human sees (W4 Ch3 lesson).
PAID_PATHS = ("/catalog", "/product/", "/api/", "/search", "/sitemap.xml")


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
    ident, price = ctx["identity"], ctx["price"]
    if not ident.verified:
        return block("cannot bill an unverified crawler", score=80.0)
    exact_raw, max_raw = ctx["exact"], ctx["max"]
    if exact_raw and max_raw:
        return paywall("only one price declaration header allowed", price)
    exact, cap = _parse(exact_raw), _parse(max_raw)
    if exact_raw and exact is None or max_raw and cap is None:
        return paywall("malformed price declaration", price)
    if exact is not None:
        if exact == price:
            return charged(f"{ident.operator} agreed exact price", price)
        return paywall(f"exact price {exact} != {price}", price)
    if cap is not None:
        if cap >= price:
            return charged(f"{ident.operator} max {cap} >= price", price)
        return paywall(f"max price {cap} below {price}", price)
    return paywall(f"{ident.operator}: price discovery", price)
