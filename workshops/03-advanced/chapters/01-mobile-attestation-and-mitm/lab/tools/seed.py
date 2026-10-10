"""
W3 Ch1 — Seed the demo store (run once, and again for a clean slate)

    - recreates the tables (SQLite by default; all data is lab data)
    - creates the legitimate customer accounts from tools/personas.py so the
      simulator can log them in
    - clears the lab's keys in the store

The attacker's farm accounts are NOT seeded: the round scripts register their
own throwaway accounts through the open /api/mobile/register endpoint, exactly
as a scalper would.

Run (from lab/):
    python tools/seed.py
"""

import os
import sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(LAB_DIR, "demo_site"))
sys.path.insert(0, HERE)

from werkzeug.security import generate_password_hash  # noqa: E402

import personas  # noqa: E402
from app import app, store  # noqa: E402
from models import User, db  # noqa: E402

LAB_KEY_PATTERNS = ("rl:*", "nonce:*", "issued:*", "spent:*", "dev:*", "weakdev:*", "mtok:*")


def main():
    created = datetime.now(timezone.utc) - timedelta(days=90)
    with app.app_context():
        db.drop_all()
        db.create_all()
        for a in personas.accounts():
            db.session.add(User(
                email=a["email"],
                password_hash=generate_password_hash(a["password"], "pbkdf2:sha256:1000"),
                address=a["address"], created_at=created, known_devices=[]))
        db.session.commit()
        print(f"✅ {User.query.count()} customer accounts")

    cleared = 0
    for pattern in LAB_KEY_PATTERNS:
        for key in store.scan_iter(pattern, count=1000):
            cleared += store.delete(key)
    print(f"✅ Cleared {cleared} lab keys in the store")


if __name__ == '__main__':
    main()
