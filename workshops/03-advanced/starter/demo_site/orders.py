"""
Order lifecycle helpers for action hooks and review tooling (contract 1.7).

A hold: an on_action("checkout"/"drop_buy") handler sets order.status = "pending" (and
usually g.outcome = "held"), commits, and returns a "202 pending review" response. The
stock stays reserved — the drop unit is not resellable while the order is under review —
and the scoreboard counts neither a purchase nor a stop until the review lands. The
review then either marks it paid (order.status = "paid"; db.session.commit()) or calls
cancel_order(), which returns the stock.

Trade-off to teach with it: deferred enforcement buys the defender time and hides the
decision boundary from the attacker, but every held order is a real customer waiting.
"""

from .models import Product, db


def cancel_order(order, reason=""):
    """Cancel an order and return its units to stock (atomic per line). Idempotent."""
    if order.status == "cancelled":
        return order
    for item in order.items:
        db.session.execute(db.update(Product).where(Product.sku == item.sku)
                           .values(stock=Product.stock + item.qty))
    order.status = "cancelled"
    order.extra = dict(order.extra or {}, cancel_reason=reason)
    db.session.commit()
    return order
