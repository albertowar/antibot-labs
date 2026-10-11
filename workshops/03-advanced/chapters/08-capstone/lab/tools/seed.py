"""
Chapter 9 — Seed the demo store (run once, and again whenever you want a clean slate)

    - recreates the tables in PostgreSQL (all data is lab data)
    - 39 aged customer accounts for the legitimate-traffic simulator
      (the 40th, the first-timer, registers during each run), plus one for
      your own captured profile
    - 40 aged "victim" accounts for Round 4, ten of which reuse a breached password
    - past orders, so real customers have a purchase history
    - writes attacks/data/combo_list.txt from the victims
    - clears the lab's keys in Redis

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

import personas  # noqa: E402
from app import PRODUCTS, DROP_SKU, app, store  # noqa: E402
from models import Order, User, db  # noqa: E402

LAB_KEY_PATTERNS = ("flow:*", "fp:*", "fph:*", "ev:*", "rl:*", "chal:*", "lr:*", "addr:*")


def main():
    rng = random.Random(9)
    now = datetime.now(timezone.utc)
    past_skus = [sku for sku in PRODUCTS if sku != DROP_SKU]
    with app.app_context():
        db.drop_all()
        db.create_all()
        accounts = ([u for u in personas.legit_users() if not u["register"]] + [personas.MINE_USER]
                    + personas.victims())
        for a in accounts:
            created = now - timedelta(days=a["age_days"])
            persona = a.get("persona")
            # The new-laptop customer's known device is their *old* laptop.
            device = personas.device_id(a["email"] + (":old" if persona == "new-laptop" else ""))
            user = User(email=a["email"], password_hash=generate_password_hash(a["password"], "pbkdf2:sha256:1000"),
                        address=a["address"], created_at=created, known_devices=[device])
            db.session.add(user)
            db.session.flush()
            for _ in range(a["prior_orders"]):
                db.session.add(Order(user_id=user.id, sku=rng.choice(past_skus), address=a["address"],
                                     created_at=created + timedelta(days=rng.randint(1, max(2, a["age_days"] - 1)))))
        db.session.commit()
        print(f"✅ {User.query.count()} accounts, {Order.query.count()} past orders")

    cleared = 0
    for pattern in LAB_KEY_PATTERNS:
        for key in store.scan_iter(pattern, count=1000):
            cleared += store.delete(key)
    print(f"✅ Cleared {cleared} lab keys in Redis")

    combo_path = os.path.join(LAB_DIR, "attacks", "data", "combo_list.txt")
    with open(combo_path, "w") as f:
        f.write("# Synthetic breach list for Round 4. Every address is @mail.example; none is real.\n")
        f.write("\n".join(personas.combo_list()) + "\n")
    print(f"✅ Wrote {os.path.relpath(combo_path, LAB_DIR)}")


if __name__ == '__main__':
    main()
