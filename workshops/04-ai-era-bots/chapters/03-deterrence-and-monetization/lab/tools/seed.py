"""Seed the catalogue: 300 synthetic products with descriptions.

Deterministic (seeded RNG) so every student has the same catalogue and the
expected-results table holds. The descriptions double as the corpus the maze
babbler trains on, so decoy pages read like the shop.

Also generates the two crawler operators' signing keys if they are missing
(tools/make_keys.py -> attacks/keys/, gitignored), so the signed-crawler rounds
and tools/legit_traffic.py can run.

    python tools/seed.py            # SQLite in data/shop.db (default)
    DATABASE_URL=... python tools/seed.py
"""

from __future__ import annotations

import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "demo_site"))
sys.path.insert(0, LAB_DIR)
sys.path.insert(0, HERE)

import make_keys  # noqa: E402

CATEGORIES = ["sneakers", "headphones", "coffee", "camping", "stationery", "kitchen"]
ADJ = ["retro", "quiet", "compact", "heavy-duty", "hand-poured", "insulated", "matte",
       "classic", "limited", "everyday", "trail", "studio", "pocket", "cast-iron", "linen"]
NOUN = {"sneakers": ["runner", "trainer", "court shoe", "slip-on", "high-top"],
        "headphones": ["over-ear set", "earbuds", "studio monitor", "headset", "wireless set"],
        "coffee": ["espresso blend", "single origin", "cold brew kit", "pour-over kettle", "grinder"],
        "camping": ["tent", "sleeping bag", "stove", "lantern", "water filter"],
        "stationery": ["notebook", "fountain pen", "planner", "pencil set", "desk pad"],
        "kitchen": ["skillet", "chef knife", "dutch oven", "mixing bowl", "cutting board"]}
PHRASES = ["built for daily use", "tested on three continents", "ships in recycled packaging",
           "pairs with everything in the range", "a favourite with our staff", "back by popular demand",
           "made in small batches", "lighter than it looks", "quietly over-engineered",
           "the colourway sells out every spring", "comes with a two-year warranty",
           "designed around one honest idea", "surprisingly good value", "a gift that gets used",
           "ready for weekend trips", "cleans up in seconds", "finished by hand"]


def make_products():
    rng = random.Random(42)
    out = []
    for i in range(1, 301):
        cat = CATEGORIES[(i - 1) % len(CATEGORIES)]
        name = f"{rng.choice(ADJ).title()} {rng.choice(NOUN[cat]).title()} #{i}"
        desc = ". ".join(rng.choice(PHRASES).capitalize() for _ in range(rng.randint(3, 5))) + "."
        out.append(dict(sku=f"p{i:03d}", name=name, price=round(rng.uniform(8, 240), 2),
                        category=cat, description=desc))
    return out


def main():
    from app import app  # noqa: WPS433  (imports the Flask app with its DB config)
    from store import Product, db
    with app.app_context():
        db.drop_all()
        db.create_all()
        db.session.bulk_insert_mappings(Product, make_products())
        db.session.commit()
        print(f"seeded {Product.query.count()} products into {app.config['SQLALCHEMY_DATABASE_URI']}")
    make_keys.main()


if __name__ == "__main__":
    main()
