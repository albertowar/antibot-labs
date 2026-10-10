"""Seed the W3 Ch6 demo store — run once, and again for a clean slate.

Everything here is synthetic. No real person, inbox, credential or breach record is
used. It creates:

  * a 60-product catalogue, 4 unlinked honeypot SKUs, and one limited drop
  * 40 "victim" accounts for Round 1 (10 reuse a breached password), plus 15
    legitimate customers (2 of whom also reused a breached password — the honest
    false-positive case the breach gate will flag)
  * data/combo_list.txt   — a synthetic stuffer combo list (10 real hits + noise)
  * data/breach_ranges/   — k-anonymity fixtures so the breach check runs offline
  * data/disposable_domains.txt — a small disposable-email blocklist
  * data/humans.json      — login credentials the legitimate simulator replays

Run (from lab/):  python tools/seed.py
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
DATA = os.path.join(LAB_DIR, "data")
sys.path.insert(0, os.path.join(LAB_DIR, "demo_site"))
sys.path.insert(0, LAB_DIR)

from werkzeug.security import generate_password_hash  # noqa: E402

from store import Product, User, db  # noqa: E402
from app import app  # noqa: E402

RNG = random.Random(6)
HASH = lambda pw: generate_password_hash(pw, "pbkdf2:sha256:1000")  # noqa: E731

BREACHED = ["hunter2", "letmein123", "password1", "qwerty123",
            "dragon2020", "iloveyou1", "sunshine7", "monkey99"]
DISPOSABLE = ["guerrillamail.com", "guerrillamailblock.com", "mailinator.com",
              "10minutemail.com", "tempmail.io", "trashmail.com", "sharklasers.com",
              "yopmail.com", "throwawaymail.com", "getnada.com"]
CATEGORIES = ["shoes", "apparel", "accessories", "bags", "socks"]
ADJ = ["Trail", "Summit", "Harbor", "Meadow", "Canyon", "Coastal", "Alpine",
       "Urban", "Classic", "Neon", "Vintage", "Studio"]
NOUN = ["Runner", "Tee", "Cap", "Tote", "Hoodie", "Short", "Jacket", "Sock",
        "Belt", "Scarf", "Glove", "Pack"]


def strong_pw():
    return "".join(RNG.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789") for _ in range(14))


def write_breach_ranges(passwords):
    """Write HIBP-style k-anonymity fixtures: data/breach_ranges/<prefix>.txt."""
    out = os.path.join(DATA, "breach_ranges")
    os.makedirs(out, exist_ok=True)
    for f in os.listdir(out):
        os.remove(os.path.join(out, f))
    buckets = {}
    for pw in passwords:
        sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        buckets.setdefault(prefix, {})[suffix] = RNG.randint(1200, 9_000_000)
    for prefix, suffixes in buckets.items():
        with open(os.path.join(out, f"{prefix}.txt"), "w") as fh:
            fh.write("\n".join(f"{suf}:{cnt}" for suf, cnt in suffixes.items()) + "\n")


def main():
    os.makedirs(DATA, exist_ok=True)
    with app.app_context():
        db.drop_all()
        db.create_all()

        # --- Catalogue (Round 3) -------------------------------------------------
        products = []
        for i in range(1, 61):
            products.append(Product(
                sku=f"cat-{i:03d}",
                name=f"{ADJ[i % len(ADJ)]} {NOUN[i % len(NOUN)]} {i}",
                price=round(RNG.uniform(6, 240), 2),
                category=RNG.choice(CATEGORIES), honeypot=False, drop=False))
        for i in range(1, 5):  # honeypot SKUs, never linked from the navigation
            products.append(Product(sku=f"hp-{i:03d}", name=f"Internal SKU {i}",
                                    price=0.0, category="internal", honeypot=True, drop=False))
        products.append(Product(sku="lab-runner-9", name="Lab Runner 9 (limited drop)",
                                price=220.0, category="shoes", honeypot=False, drop=True))
        db.session.add_all(products)

        # --- Users ---------------------------------------------------------------
        users = []
        combos = []           # the stuffer's combo list (email:password)
        # 40 victims; the first 10 reuse a breached password and are real hits.
        for i in range(40):
            email = f"victim{i:03d}@example.com"
            if i < 10:
                pw, breached = BREACHED[i % len(BREACHED)], True
                combos.append(f"{email}:{pw}")             # a real, breached hit
            else:
                pw, breached = strong_pw(), False
            users.append(User(id=f"v{i:03d}", email=email, password_hash=HASH(pw),
                              password_breached=breached))
        # 15 legitimate customers; humans 13 and 14 reused a breached password.
        humans = []
        for i in range(15):
            email = f"human{i:02d}@mail.example"
            breached = i in (13, 14)
            pw = BREACHED[i % len(BREACHED)] if breached else strong_pw()
            users.append(User(id=f"h{i:02d}", email=email, password_hash=HASH(pw),
                             password_breached=breached))
            humans.append({"email": email, "password": pw, "breached": breached})
        db.session.add_all(users)
        db.session.commit()

        # --- Fixtures ------------------------------------------------------------
        # Combo list: 10 real breached hits + ~990 non-matching noise pairs.
        for _ in range(990):
            combos.append(f"user{RNG.randint(10000, 99999)}@mail.example:{strong_pw()}")
        RNG.shuffle(combos)
        with open(os.path.join(DATA, "combo_list.txt"), "w") as fh:
            fh.write("\n".join(combos) + "\n")

        # Breach corpus: the 8 breached passwords (and nothing else).
        write_breach_ranges(BREACHED)

        with open(os.path.join(DATA, "disposable_domains.txt"), "w") as fh:
            fh.write("# synthetic disposable-email blocklist (lab)\n")
            fh.write("\n".join(DISPOSABLE) + "\n")

        with open(os.path.join(DATA, "humans.json"), "w") as fh:
            json.dump(humans, fh, indent=2)

    print(f"seeded: 61 products (+4 honeypots), 55 users, "
          f"{len(combos)} combos (10 hits), breach corpus of {len(BREACHED)}.")
    print("next:  python demo_site/app.py   then run a round's attack + checkpoint.")


if __name__ == "__main__":
    main()
