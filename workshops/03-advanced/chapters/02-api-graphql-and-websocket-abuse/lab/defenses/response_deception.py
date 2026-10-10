"""L5 — response deception (Round 5, support module).

A 403 teaches the attacker exactly where your detection line is: they adjust and
retry. Deception keeps serving 200 OK with data that is plausibly wrong, so a
scraper banks poisoned prices and inventory and does not learn it was caught.
Use it sparingly and only on read endpoints whose data you can safely distort,
and never on an action with a real-world side effect (a payment, a password
change).

This ships complete; it is not the Round 5 exercise. The poison here is
deterministic so the lab's scoreboard can show it: prices are inflated 12% and
inventory is pinned to a fixed number. In production you would jitter both so the
poisoned values are not obviously synthetic.

Trade-off and false positives: anything you poison, a *misclassified real user*
also receives. Deception multiplies the cost of a false positive — a real
customer seeing a wrong price is worse than a clean block — so gate it on a high
score and log every poisoned response for audit.
"""

from __future__ import annotations

import copy

POISON_PRICE_MULT = 1.12
POISON_INVENTORY = 137


def poison_products(items: list[dict]) -> list[dict]:
    out = copy.deepcopy(items)
    for item in out:
        if "price" in item:
            item["price"] = round(item["price"] * POISON_PRICE_MULT, 2)
        if "inventory" in item:
            item["inventory"] = POISON_INVENTORY
    return out


def should_deceive(outcome: str) -> bool:
    return outcome in ("challenge", "block")
