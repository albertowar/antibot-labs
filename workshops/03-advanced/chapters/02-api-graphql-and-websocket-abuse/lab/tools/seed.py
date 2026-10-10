"""Seed the demo store: products, users, orders, and the persisted-query allowlist.

Run once before the session (and again any time you want a clean catalogue):

    python tools/seed.py

The catalogue is 500 products so pagination and id-enumeration are worth doing;
a handful are ``hidden`` (internal SKUs never linked from the UI) so the Round 1
enumeration attack has something to find that browsing never would. The
persisted-query allowlist is written from the exact operation strings the
first-party client (tools/legit_traffic.py) sends, so their SHA-256 hashes match
at runtime — that is what makes the Round 3 allowlist accept real clients and
reject everything else.
"""

from __future__ import annotations

import json
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "demo_site"))
sys.path.insert(0, os.path.join(LAB_DIR, "defenses"))

from werkzeug.security import generate_password_hash  # noqa: E402

from app import app  # noqa: E402  (imports create the Flask app; no server starts)
from models import Order, Product, User, db  # noqa: E402

DATA = os.path.join(LAB_DIR, "data")

# The first-party client's operations. These exact strings become the trusted
# documents (Round 3). legit_traffic.py sends them verbatim.
PERSISTED_QUERIES = {
    "Products": "query Products { products(first: 20) { id sku name price inventory } }",
    "Product": "query Product($id: Int!) { product(id: $id) { id sku name price inventory } }",
    "AccountOrders": "query AccountOrders { users(first: 1) { id email orders { id sku } } }",
}

NAMED = [
    ("lab-runner-9", "Lab Runner 9 (limited drop)", 220.0, 50),
    ("trail-socks", "Trail socks, 3-pack", 18.0, 400),
    ("laces-neon", "Neon laces", 6.0, 900),
    ("cap-classic", "Classic cap", 28.0, 150),
]

# Known first-party accounts (synthetic). Round 5 harvests victim@example.com.
USERS = [
    ("runner@example.com", "Sneakers123!"),
    ("victim@example.com", "Hunter2day!"),
]


def main():
    os.makedirs(DATA, exist_ok=True)
    with open(os.path.join(DATA, "persisted_queries.json"), "w") as fh:
        json.dump(PERSISTED_QUERIES, fh, indent=2)

    with app.app_context():
        db.drop_all()
        db.create_all()

        for i, (sku, name, price, inv) in enumerate(NAMED, start=1):
            db.session.add(Product(id=i, sku=sku, name=name, price=price, inventory=inv))
        for pid in range(len(NAMED) + 1, 501):
            hidden = pid >= 490  # ids 490-500 are internal SKUs, never linked
            sku = f"internal-{pid}" if hidden else f"catalog-{pid}"
            db.session.add(Product(id=pid, sku=sku, name=f"Catalogue item {pid}",
                                   price=round(9.0 + (pid % 40) * 1.5, 2),
                                   inventory=50 + (pid % 100), hidden=hidden))

        users = []
        for email, pw in USERS:
            u = User(id=secrets.token_hex(8), email=email,
                     password_hash=generate_password_hash(pw),
                     api_secret=secrets.token_hex(16))
            users.append(u)
            db.session.add(u)
        db.session.flush()
        for u in users:
            for sku in ("lab-runner-9", "trail-socks"):
                db.session.add(Order(user_id=u.id, sku=sku))
        db.session.commit()

        print(f"[seed] {Product.query.count()} products "
              f"({Product.query.filter_by(hidden=True).count()} hidden), "
              f"{User.query.count()} users, {Order.query.count()} orders")
        print(f"[seed] persisted queries: {len(PERSISTED_QUERIES)} -> data/persisted_queries.json")


if __name__ == "__main__":
    main()
