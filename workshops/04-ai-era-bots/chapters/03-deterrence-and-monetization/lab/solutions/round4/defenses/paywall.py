"""Round 4 defense [REFERENCE SOLUTION] — pay-per-crawl over HTTP 402.

A clone of the Cloudflare pay-per-crawl exchange (2025-26), the first deployed protocol that turns
"no" into "yes, for a price":

  reactive   crawler GET /product/x                 -> 402, `crawler-price: USD 0.01`
             crawler GET /product/x + `crawler-exact-price: USD 0.01`
                                                     -> 200, `crawler-charged: USD 0.01`
  proactive  crawler GET /product/x + `crawler-max-price: USD 0.05`
                                                     -> 200, charged the configured price if
                                                        <= max, else 402

Only one price-declaration header per request; anything malformed is a 402. A billing event exists
only for a *verified* identity (bot_identity.py): the ledger is keyed on the operator the signature
names. That is why Round 2's enforcement sits in front: an unverified "LabTrainBot" is refused,
never billed.

How it reaches the wire: a 402 and a "charged" 200 are not new verdicts either (the gate's set is
closed). The CHECK below runs at LADDER[4], calls evaluate() and records the answer in
`ctx.attrs["paywall"]`; `demo_site/ext/deterrence.py` turns it into the 402 (`g.outcome =
"paywalled"`) or lets the page through and stamps `crawler-charged`, writes the ledger under
`lab:ledger:*` and sets `g.outcome = "charged"`. The scoreboard counts each in its own column.

TODO 1 (evaluate) and TODO 2 (PAID_PATHS) are done here. TODO 2 is the lesson most teams learn in
production: the paywall was wired on the HTML pages and the catalogue leaked for free through the
JSON API, search, the sitemap and the feed. Every content carrier must sit behind the same policy.

What this never reaches: the stealth crawler of Round 3. Monetization governs the honest;
deterrence and detection handle the rest. And the honest can still walk away: most 402s in the wild
are never paid.
"""

from __future__ import annotations

from collections import namedtuple

from . import bot_identity, crawl_policy
from .pipeline import Check, Signal, Verdict

PAYWALL = {
    "enabled": True,
    "price_usd": 0.01,
    "purposes": ("ai-train", "ai-input"),   # search stays free: we want the referrals
}

# TODO 2 done: every carrier of catalogue data, not just the pages a human sees.
PAID_PATHS = ("/products", "/product/", "/search", "/sitemap.xml", "/feed.xml", "/api/products", "/api/search")

# What evaluate() answers. action: "free" | "block" | "paywall" | "charged".
Offer = namedtuple("Offer", "action reason price")


def free(reason: str) -> Offer:
    return Offer("free", reason, 0.0)


def block(reason: str) -> Offer:
    return Offer("block", reason, 0.0)


def paywall(reason: str, price: float) -> Offer:
    return Offer("paywall", reason, price)


def charged(reason: str, price: float) -> Offer:
    return Offer("charged", reason, price)


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


def evaluate(ident, price: float, exact, cap) -> Offer:
    """The 402 exchange."""
    if not ident.verified:
        return block("cannot bill an unverified crawler")
    if exact and cap:
        return paywall("only one price declaration header allowed", price)
    exact_usd, cap_usd = _parse(exact), _parse(cap)
    if exact and exact_usd is None or cap and cap_usd is None:
        return paywall("malformed price declaration", price)
    if exact_usd is not None:
        if exact_usd == price:
            return charged(f"{ident.operator} agreed the exact price", price)
        return paywall(f"exact price {exact_usd} != {price}", price)
    if cap_usd is not None:
        if cap_usd >= price:
            return charged(f"{ident.operator} max {cap_usd} >= price", price)
        return paywall(f"max price {cap_usd} below {price}", price)
    return paywall(f"{ident.operator}: price discovery", price)


def _check(ctx):
    """Given: price a licensed purpose's request for a paid path."""
    if crawl_policy.exempt(ctx.path) or not applies(ctx.path):
        return None
    ident = bot_identity.identify(ctx)
    if not ident.operator or crawl_policy.effective_rules(ctx.level).get(ident.purpose) != "licensed":
        return None
    offer = evaluate(ident, float(PAYWALL["price_usd"]), ctx.header("crawler-exact-price"),
                     ctx.header("crawler-max-price"))
    ctx.attrs["paywall"] = offer
    ctx.note(paywall=offer.action, paywall_reason=offer.reason[:120], price=offer.price)
    if offer.action == "block":
        return Verdict("block", 80, (Signal("paywall", "unbillable", 80, offer.reason[:160]),))
    return [Signal("paywall", offer.action, 0, offer.reason[:120])]


CHECK = Check("paywall", _check)
