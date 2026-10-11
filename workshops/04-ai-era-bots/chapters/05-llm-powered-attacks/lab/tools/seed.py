"""Seed the W4 Ch5 demo store — run once, and again for a clean slate.

Everything here is synthetic. No real person, inbox or credential is used. It
creates:

  * a 60-product catalogue plus 4 honeypot products that are never shown to anyone
  * 20 legitimate reviewer accounts with purchase history (one opened today; two
    never bought the product they review)
  * 40 "farm" accounts the attacker registered this morning (Round 1)
  * 9 "mule" accounts with one purchase each (Round 4: the injector buys first so
    its reviews are verified)
  * data/human_reviews.json   — the two legitimate reviewer cohorts (Rounds 1, 4)
  * data/farm_accounts.json   — the farm's account list
  * data/disposable_domains.txt — a small disposable-email blocklist

Run (from lab/):  python tools/seed.py
"""

from __future__ import annotations

import json
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LAB_DIR = os.path.dirname(HERE)
DATA = os.path.join(LAB_DIR, "data")
sys.path.insert(0, os.path.join(LAB_DIR, "demo_site"))
sys.path.insert(0, LAB_DIR)

from werkzeug.security import generate_password_hash  # noqa: E402

from store import Product, Purchase, Review, User, db  # noqa: E402
from app import app  # noqa: E402

RNG = random.Random(45)
HASH = lambda pw: generate_password_hash(pw, "pbkdf2:sha256:1000")  # noqa: E731
DAY = 86400

DISPOSABLE = ["guerrillamail.com", "mailinator.com", "10minutemail.com", "tempmail.io",
              "trashmail.com", "sharklasers.com", "yopmail.com", "getnada.com"]
CATEGORIES = ["shoes", "apparel", "accessories", "bags", "kitchen"]
ADJ = ["Trail", "Summit", "Harbor", "Meadow", "Canyon", "Coastal", "Alpine",
       "Urban", "Classic", "Neon", "Vintage", "Studio"]
NOUN = ["Runner", "Tee", "Cap", "Tote", "Hoodie", "Short", "Jacket", "Sock",
        "Belt", "Scarf", "Glove", "Pack"]
BLURBS = ["Everyday staple, cut for layering.", "Lightweight and quick to dry.",
          "Built for the commute, happy on the trail.", "Recycled shell, taped seams.",
          "Our best-selling shape, back in new colours.", "Sized true; order your usual."]
HONEYPOTS = [("hp-101", "Harbor Glove 61", 24.00), ("hp-102", "Studio Pack 62", 89.50),
             ("hp-103", "Canyon Belt 63", 31.00), ("hp-104", "Meadow Scarf 64", 19.90)]

# Round 1 reviewer cohort: ordinary, varied prose. Two trip the pre-wired content
# heuristics on purpose (an exact duplicate pair, and one very short review) —
# that friction is a real cost the scoreboard must show.
HUMAN_R1 = [
    ("cat-001", 5, "Comfortable straight out of the box, no blisters on a long walk. Laces run a touch long."),
    ("cat-002", 4, "Nice weight for spring. The grey is darker than the photo suggests."),
    ("cat-003", 5, "Great product, fast delivery."),
    ("cat-003", 5, "Great product, fast delivery."),             # exact duplicate -> held
    ("cat-004", 3, "ok tote. handles could be longer, hard to get over a winter coat"),
    ("cat-005", 5, "Love it!"),                                   # too short -> held
    ("cat-006", 2, "Zip jammed after two weeks. Support replaced it, hence 2 not 1."),
    ("cat-007", 4, "Boils a litre in about three minutes. Lid is fiddly one-handed."),
    ("cat-008", 5, "Third pair of these socks. They just last."),
    ("cat-009", 4, "Good leather belt, the buckle scratches easily though."),
    ("cat-010", 5, "Bought it as a gift and it gets worn constantly. Sizing was spot on."),
    ("cat-001", 4, "Runs slightly narrow. Went half a size up and they are perfect now."),
    ("cat-002", 1, "Seam came apart on the first wash. Returned it."),
    ("cat-004", 5, "I use this tote for the market every week; it has carried a heavy load without complaint."),
    ("cat-006", 4, "Warm, light, packs small. Hood is a little shallow for a lot of hair."),
    ("cat-007", 5, "Replaced a kettle that lasted years. So far it is just as good."),
    ("cat-005", 4, "Decent shorts for the gym and the pocket zip is useful. Fabric is a bit shiny."),
    ("cat-008", 5, "Arrived today and already on my feet. Soft and snug, no slipping."),
    ("cat-009", 3, "Fine but unremarkable. You get what you pay for."),
    ("cat-010", 4, "The cap keeps its shape after rain and the colour is true to the listing."),
]
# Round 4 reviewer cohort: ordinary reviews, three of which contain everyday
# phrases a naive injection deny-list misreads as an attack. Real people write
# these; the regex blocks them, the architectural guard does not.
HUMAN_R4 = [
    ("cat-001", 5, "Ignore the instructions on the box about a break-in period, they are comfy from day one."),
    ("cat-002", 4, "You are now looking at the only tee I wear to the gym. I bought two."),
    ("cat-003", 4, "Disregard the one-star reviews about sizing; it runs true if you check the chart."),
    ("cat-004", 5, "Carried groceries, books and a laptop all week and it still looks new."),
    ("cat-005", 3, "Pockets are shallow and my phone slipped out once. Otherwise fine."),
    ("cat-006", 4, "Kept me dry in a real downpour. Sleeves are generous, which I like."),
    ("cat-007", 5, "Fast, quiet, and the auto-off actually works. Happy with it."),
    ("cat-008", 4, "Snug without being tight. They wash well and keep their shape."),
    ("cat-009", 2, "Strap frayed within a month. Expected better at this price."),
    ("cat-010", 5, "Exactly as pictured and it fits well. Would buy the other colours."),
    ("cat-001", 4, "Great for short runs. The sole is firmer than I expected, took a day to adjust."),
    ("cat-002", 5, "Soft cotton, no shrinkage so far. My go-to layer under a jacket."),
    ("cat-003", 3, "Does the job but the stitching is uneven on one side."),
    ("cat-004", 5, "Roomy and light. The inner pocket is handy for keys and a card."),
    ("cat-005", 4, "Comfortable waistband. Could use a back pocket but I manage without."),
    ("cat-006", 5, "Light enough to pack, warm enough for an autumn evening. Good value."),
    ("cat-007", 4, "Pours cleanly with no drips. The handle stays cool, which is a plus."),
    ("cat-008", 5, "Cushioned where it counts. No blisters after a full day on my feet."),
    ("cat-009", 4, "Solid everyday belt. The leather is softening nicely with use."),
    ("cat-010", 4, "Keeps the sun off and folds flat in a bag. The brim is a bit stiff at first."),
]


def strong_pw():
    return "".join(RNG.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789") for _ in range(14))


def main():
    os.makedirs(DATA, exist_ok=True)
    now = time.time()
    with app.app_context():
        db.drop_all()
        db.create_all()

        # --- Catalogue (Round 3) ---------------------------------------------------
        products = []
        for i in range(1, 61):
            products.append(Product(
                sku=f"cat-{i:03d}",
                name=f"{ADJ[i % len(ADJ)]} {NOUN[i % len(NOUN)]} {i}",
                price=round(RNG.uniform(9, 240), 2),
                category=CATEGORIES[i % len(CATEGORIES)],
                blurb=RNG.choice(BLURBS), honeypot=False))
        for sku, name, price in HONEYPOTS:
            products.append(Product(sku=sku, name=name, price=price,
                                    category="internal", blurb="", honeypot=True))
        db.session.add_all(products)

        # --- Legitimate reviewers (Rounds 1 and 4) --------------------------------
        # Established accounts with a purchase for the SKU they review, so the
        # identity signals clear them. Two Round-1 reviewers never bought (gift /
        # in-store), one account opened today: the honest false-positive edge.
        reviewers = {}

        def reviewer(email, age_days, bought_skus):
            if email not in reviewers:
                reviewers[email] = True
                db.session.add(User(email=email, password_hash=HASH(strong_pw()),
                                    created_at=now - age_days * DAY, origin="organic"))
                for sku in bought_skus:
                    db.session.add(Purchase(email=email, sku=sku, ts=now - age_days * DAY / 2))

        human_reviews = {"round1": [], "round4": []}
        for cohort, rows in (("round1", HUMAN_R1), ("round4", HUMAN_R4)):
            for idx, (sku, rating, text) in enumerate(rows):
                email = f"{cohort}_reviewer_{idx:02d}@mail.example"
                # two Round-1 reviewers (idx 4, 5) did not buy; idx 2 opened today
                bought = [] if (cohort == "round1" and idx in (4, 5)) else [sku]
                age = 0.03 if (cohort == "round1" and idx == 2) else RNG.uniform(40, 900)
                reviewer(email, age, bought)
                human_reviews[cohort].append(
                    {"email": email, "sku": sku, "rating": rating, "text": text,
                     "fp": f"human-fp-{cohort}-{idx:02d}", "ip_index": idx})

        # --- Round 1 farm accounts -------------------------------------------------
        # 40 accounts registered this morning, no purchases. The farm shares a few
        # devices and egress IPs across all of them — the signal it cannot hide.
        farm = [{"email": f"shopper_{i:04d}@mail.example", "sku": f"cat-{(i % 60) + 1:03d}",
                 "created_days": RNG.uniform(0.01, 0.3)} for i in range(40)]
        for a in farm:
            db.session.add(User(email=a["email"], password_hash=HASH(strong_pw()),
                                created_at=now - a["created_days"] * DAY, origin="farm"))

        # --- Round 4 mule accounts -------------------------------------------------
        # The injector needs verified purchases, so these 9 accounts each bought one
        # product. Buying is the attacker's real cost; the lab just pre-pays it.
        for i in range(9):
            email = f"mule_{i:02d}@mail.example"
            sku = "cat-001"
            db.session.add(User(email=email, password_hash=HASH(strong_pw()),
                                created_at=now - RNG.uniform(10, 60) * DAY, origin="mule"))
            db.session.add(Purchase(email=email, sku=sku, ts=now - 5 * DAY))

        db.session.commit()

        with open(os.path.join(DATA, "human_reviews.json"), "w") as fh:
            json.dump(human_reviews, fh, indent=2)
        with open(os.path.join(DATA, "farm_accounts.json"), "w") as fh:
            json.dump(farm, fh, indent=2)
        with open(os.path.join(DATA, "disposable_domains.txt"), "w") as fh:
            fh.write("# synthetic disposable-email blocklist (lab)\n")
            fh.write("\n".join(DISPOSABLE) + "\n")

    print(f"seeded: 60 products (+4 honeypots), {len(reviewers)} reviewers, "
          f"40 farm accounts, 9 mule accounts.")
    print("next:  python demo_site/app.py   then run a round's attack + checkpoint.")


if __name__ == "__main__":
    main()
