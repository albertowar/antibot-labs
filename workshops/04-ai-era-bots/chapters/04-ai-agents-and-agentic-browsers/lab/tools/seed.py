"""
W4 Ch4 — Seed the demo store (run once, and again whenever you want a clean slate)

    - recreates the tables (all data is lab data)
    - 39 aged customer accounts for the legitimate-traffic simulator (the 40th, the
      first-timer, registers during each run)
    - 5 aged attacker-owned accounts the Round 1–3 agent logs in with
    - past orders, so real customers have a purchase history
    - clears the lab's keys in Redis (with fakeredis the store process keeps its own
      state, so restart it after seeding)
    - makes sure the operator keys exist (tools/make_keys.py)

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
from app import DROP_SKU, PRODUCTS, app, store  # noqa: E402
from models import Order, User, db  # noqa: E402


def main():
    rng = random.Random(9)
    now = datetime.now(timezone.utc)
    past_skus = [sku for sku in PRODUCTS if sku != DROP_SKU]
    with app.app_context():
        db.drop_all()
        db.create_all()
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
        print(f"✅ {User.query.count()} accounts, {Order.query.count()} past orders")
    cleared = sum(store.delete(k) for k in store.scan_iter("*", count=1000))
    print(f"✅ Cleared {cleared} lab keys ({'external Redis' if os.environ.get('REDIS_URL') else 'this process'})")
    make_keys.main()


if __name__ == '__main__':
    main()
