"""
Round 5 (level 5, support module) - response deception.

A 403 teaches the attacker exactly where your detection line is: they adjust and retry. Deception keeps serving
200 OK with data that is plausibly wrong, so a scraper banks poisoned prices and inventory and does not learn it
was caught. Use it sparingly and only on read endpoints whose data you can safely distort, and never on an action
with a real-world side effect (a payment, a password change).

This ships complete; it is not the Round 5 exercise. The route that serves it is /api/v2/inventory/<sku>
(demo_site/ext/api_v2.py): when the ladder's decision for that read is a challenge or a block, the route answers
200 with ``poison`` applied instead of refusing. The poison here is deterministic so the lab can show it: prices
are inflated 12% and stock is pinned to a fixed number. In production you would jitter both so the poisoned
values are not obviously synthetic.

Trade-off and false positives: anything you poison, a *misclassified real user* also receives. Deception
multiplies the cost of a false positive - a real customer seeing a wrong price is worse than a clean block - so
gate it on a high score and log every poisoned response for audit (the decision log records them as `deceived`).
"""

POISON_PRICE_MULT = 1.12
POISON_STOCK = 137


def poison(item):
    out = dict(item)
    if "price_cents" in out:
        out["price_cents"] = round(out["price_cents"] * POISON_PRICE_MULT)
        out["price"] = out["price_cents"] / 100
    if "stock" in out:
        out["stock"] = POISON_STOCK
    return out


def should_deceive(action):
    return action in ("challenge", "block")
