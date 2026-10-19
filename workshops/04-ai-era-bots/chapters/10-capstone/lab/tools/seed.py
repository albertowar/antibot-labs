"""
W4 Ch10 Capstone — Seed the demo store (run once, and again whenever you want a clean slate)

    - recreates the tables (all data is lab data)
    - 120 catalogue products (deterministic), the limited drop (500 units, one
      per account), and three honeypot SKUs nobody is ever shown
    - 46 aged customer accounts for the legitimate-traffic simulator (the 47th,
      the first-timer, registers during each run)
    - 6 aged attacker-owned accounts (the dark cloud agent, the injector's mules)
    - past orders, so real customers have a purchase history
    - clears the lab's keys in Redis (with fakeredis the store process keeps its
      own state, so restart it after seeding)
    - makes sure the operator keys and key directories exist (tools/make_keys.py)

Run (from lab/):
    python tools/seed.py
"""

import os
import random
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "demo_site"))
sys.path.insert(0, HERE)

from werkzeug.security import generate_password_hash  # noqa: E402

import make_keys  # noqa: E402
import personas  # noqa: E402

CATEGORIES = ["trail shoes", "packs", "headlamps", "jackets", "poles", "camp kitchen"]
ADJ = ["Ridge", "Alpine", "Summit", "Tundra", "Cinder", "Granite", "Fjord", "Sierra", "Dune", "Mesa",
       "Boreal", "Canyon", "Glacier", "Juniper", "Lichen"]
NOUN = {"trail shoes": ["Runner", "Trainer", "Approach Shoe", "Hiker", "Fell Shoe"],
        "packs": ["Daypack", "Vest", "Haul Bag", "Fastpack", "Hip Pack"],
        "headlamps": ["Headlamp", "Lantern", "Beacon", "Torch", "Clip Light"],
        "jackets": ["Shell", "Windbreaker", "Fleece", "Puffy", "Anorak"],
        "poles": ["Pole", "Folding Pole", "Trekking Pole", "Staff", "Z-Pole"],
        "camp kitchen": ["Stove", "Kettle", "Pot Set", "Mug", "Spork"]}
PHRASES = ["built for daily use", "tested on three continents", "ships in recycled packaging",
           "pairs with everything in the range", "a favourite with our staff", "back by popular demand",
           "made in small batches", "lighter than it looks", "quietly over-engineered",
           "the colourway sells out every spring", "comes with a two-year warranty",
           "designed around one honest idea", "surprisingly good value", "a gift that gets used",
           "ready for weekend trips", "cleans up in seconds", "finished by hand"]
DROP_SKU = "lab-runner-9"
DROP_STOCK = int(os.environ.get("DROP_STOCK", "500"))
HONEYPOTS = [("cat-901", "Boreal Beacon Pro (archive)", 74.0), ("cat-902", "Mesa Fastpack 18 (archive)", 139.0),
             ("cat-903", "Sierra Kettle Ti (archive)", 58.0)]


def make_products():
    rng = random.Random(42)
    out = [dict(sku=DROP_SKU, name="Lab Runner 9 (limited drop)", price=220.0, category="trail shoes",
                description="Launch-day drop. One per account. Lightweight, durable, shipped within two days.",
                drop=True, stock=DROP_STOCK)]
    for i in range(1, 121):
        cat = CATEGORIES[(i - 1) % len(CATEGORIES)]
        name = f"{rng.choice(ADJ)} {rng.choice(NOUN[cat])} {i}"
        desc = ". ".join(rng.choice(PHRASES).capitalize() for _ in range(rng.randint(3, 5))) + "."
        out.append(dict(sku=f"cat-{i:03d}", name=name, price=round(rng.uniform(8, 240), 2), category=cat,
                        description=desc))
    for sku, name, price in HONEYPOTS:
        out.append(dict(sku=sku, name=name, price=price, category="archive", honeypot=True,
                        description="Archived listing. Not shown to customers."))
    return out


def main():
    from app import app, store  # noqa: WPS433
    from models import Order, Product, User, db
    rng = random.Random(9)
    now = datetime.now(timezone.utc)
    with app.app_context():
        db.drop_all()
        db.create_all()
        db.session.bulk_insert_mappings(Product, make_products())
        past_skus = [p["sku"] for p in make_products() if not p.get("drop") and not p.get("honeypot")]
        accounts = [u for u in personas.legit_users() if not u["register"]] + personas.owner_accounts()
        for a in accounts:
            created = now - timedelta(days=a["age_days"])
            user = User(email=a["email"], password_hash=generate_password_hash(a["password"], "pbkdf2:sha256:1000"),
                        address=a["address"], created_at=created, known_devices=[personas.device_id(a["email"])])
            db.session.add(user)
            db.session.flush()
            for _ in range(a["prior_orders"]):
                db.session.add(Order(user_id=user.id, sku=rng.choice(past_skus), address=a["address"],
                                     created_at=created + timedelta(days=rng.randint(1, max(2, a["age_days"] - 1)))))
        db.session.commit()
        print(f"✅ {Product.query.count()} products (120 catalogue + drop + 3 honeypots), "
              f"{User.query.count()} accounts, {Order.query.count()} past orders")
    cleared = sum(store.delete(k) for k in store.scan_iter("*", count=1000))
    print(f"✅ Cleared {cleared} lab keys ({'external Redis' if os.environ.get('REDIS_URL') else 'this process'})")
    make_keys.main()


if __name__ == '__main__':
    main()
