"""
Deterministic seed data. Everything derives from LAB_SEED (default 1337), so a
lab's expected-results table is reproducible on any machine.

    120 products  p001..p120, six categories, 20 each
      2 drops     lab-runner-9 (one per account) and lab-hoodie-1 (DROP_STOCK units)
    300 users     user000..user299@example.test; users 000-029 use a top-100 password
                  (the credential-stuffing subset); plus mallory@example.test, the
                  attacker's own legitimately registered account
    200 gift cards, ~600 reviews, ~800 historical orders

Password hashing is PBKDF2-SHA256 at LAB_HASH_ITERS (5000). That is a lab
speed setting: production uses Argon2id with current OWASP parameters, and
every login attempt, including the ones you block, pays that cost.

    python demo_site/seed.py            # (re)seed the configured database
    python demo_site/seed.py --reset    # drop and recreate everything
"""

import hashlib
import hmac
import os
import random
import sys
from datetime import timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from demo_site.models import Address, Decision, GiftCard, Newsletter, Order, OrderItem, Product, Review, User, db, utcnow  # noqa: E402

CATEGORIES = ["shoes", "packs", "jackets", "headlamps", "poles", "kitchen"]
NOUNS = {
    "shoes": ["Trail Runner", "Approach Shoe", "Hiking Boot", "Ridge Sandal"],
    "packs": ["Daypack", "Summit Pack", "Hip Pack", "Haul Bag"],
    "jackets": ["Shell Jacket", "Down Hoodie", "Wind Shirt", "Fleece Pullover"],
    "headlamps": ["Headlamp", "Lantern", "Beacon", "Trail Torch"],
    "poles": ["Trekking Pole", "Carbon Pole", "Folding Pole", "Snow Pole"],
    "kitchen": ["Camp Stove", "Titanium Pot", "Spork Set", "Press Mug"],
}
ADJECTIVES = ["Ridge", "Cirque", "Tarn", "Scree", "Alpenglow"]
COLORWAYS = ["Ash", "Moss", "Ember", "Slate", "Glacier", "Ochre", "Night", "Lichen"]
SIZES = {"shoes": ["7", "8", "9", "10", "11", "12"], "jackets": ["XS", "S", "M", "L", "XL"],
         "packs": ["S/M", "M/L"], "headlamps": [], "poles": ["100", "110", "120", "130"], "kitchen": []}
BLURBS = ["Built for long days above the treeline.", "Light enough to forget, tough enough to trust.",
          "Our most-requested piece, back in {colorway}.", "Designed with the Kestrel trail crew.",
          "Packs small. Works hard.", "The one you grab when the forecast is wrong."]

N_USERS = 300
ATTACKER_ACCOUNT = ("mallory@example.test", "mallory-owns-this-1")
WORDS = ["amber", "basil", "cedar", "delta", "ember", "fjord", "gamma", "harbor", "indigo", "juniper",
         "kestrel", "lumen", "maple", "nectar", "onyx", "pepper", "quartz", "raven", "saffron", "tundra",
         "umber", "violet", "willow", "zephyr"]
FIRST = ["Ada", "Ben", "Chloe", "Dev", "Esme", "Finn", "Grace", "Hugo", "Iris", "Jonas", "Kai", "Lena",
         "Milo", "Nora", "Omar", "Priya", "Quinn", "Rosa", "Sam", "Tess", "Uma", "Vik", "Wren", "Yara", "Zoe"]
LAST = ["Alder", "Birch", "Cole", "Dune", "Ellis", "Frost", "Gale", "Hart", "Ives", "Juno", "Kerr", "Lowe",
        "Moss", "Nash", "Oak", "Pike", "Reed", "Sage", "Thorne", "Vale", "Wilde", "York"]
CITIES = [("Denver", "80202", "US"), ("Portland", "97201", "US"), ("Boulder", "80301", "US"),
          ("Seattle", "98101", "US"), ("Chamonix", "74400", "FR"), ("Innsbruck", "6020", "AT"),
          ("Oslo", "0150", "NO"), ("Fort William", "PH33", "GB")]
REVIEW_TITLES = ["Exactly what I needed", "Solid, no surprises", "Runs a bit small", "Three seasons in",
                 "Worth the wait", "Replaced my old one", "Good, not great", "Lighter than expected"]
REVIEW_BODIES = ["Took it on a four-day loop and it held up. Would buy again.",
                 "Fit is true to size for me. Colour matches the photos.",
                 "Zips feel a little cheap but the fabric is excellent.",
                 "Second one I own. The first lasted five years.",
                 "Shipping was quick and the packaging was minimal, which I like.",
                 "Does the job. Nothing fancy, nothing missing."]

WORDLIST = os.path.join(os.path.dirname(__file__), "..", "data", "wordlists", "passwords_top.txt")


def _hash(password, salt, iters):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)


def password_for(i, seed=1337):
    """The password of user i. Users 0-29 reuse a top-100 password (the stuffing subset)."""
    rng = random.Random(seed * 1000 + i)
    if i < 30:
        with open(WORDLIST) as f:
            common = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return common[i % len(common)]
    return f"{rng.choice(WORDS)}-{rng.choice(WORDS)}-{rng.randint(10, 99)}"


def username(i):
    return f"user{i:03d}@example.test"


def weak_users():
    """(email, password) for the stuffing subset. Attack scripts for ATO chapters start here."""
    return [(username(i), password_for(i)) for i in range(30)]


def set_password(user, password, iters):
    user.password_salt = hashlib.sha256(f"salt:{user.email}".encode()).digest()[:16]
    user.password_hash = _hash(password, user.password_salt, iters)


def check_password(user, password, iters):
    """Constant-time-ish compare. Returns True on a match."""
    if user is None:
        _hash(password, b"dummy-salt", iters)      # pay the cost even for unknown users
        return False
    return hmac.compare_digest(_hash(password, user.password_salt, iters), user.password_hash)


def product_rows(seed):
    rng = random.Random(seed)
    rows = []
    for i in range(120):
        cat = CATEGORIES[i % 6]
        adj = ADJECTIVES[(i // 6) % 5]
        noun = NOUNS[cat][(i // 30) % 4]
        colorway = COLORWAYS[(i * 7) % len(COLORWAYS)]
        price = 1999 + ((i * 3701) % 19000)
        rows.append(Product(sku=f"p{i + 1:03d}", name=f"{adj} {noun}", category=cat, price_cents=price,
                            blurb=rng.choice(BLURBS).format(colorway=colorway), colorway=colorway,
                            sizes=SIZES[cat], stock=500, rating=0.0))
    return rows


def drop_rows(drop_stock):
    past = utcnow() - timedelta(minutes=1)
    return [
        Product(sku="lab-runner-9", name="Lab Runner 9", category="shoes", price_cents=22000, colorway="Night",
                blurb="Numbered release. One pair per account.", sizes=SIZES["shoes"], stock=drop_stock,
                is_drop=True, drop_at=past, max_per_account=1),
        Product(sku="lab-hoodie-1", name="Kestrel One Hoodie", category="jackets", price_cents=8900, colorway="Ember",
                blurb="The drop. When it is gone, it is gone.", sizes=SIZES["jackets"], stock=drop_stock,
                is_drop=True, drop_at=past, max_per_account=0),
    ]


def seed_all(seed=1337, drop_stock=50, hash_iters=5000, reset=False):
    """Fill an empty database. With reset=True, wipe it first. Returns a summary dict."""
    if reset:
        db.drop_all()
    db.create_all()
    if Product.query.count():
        return {"seeded": False}
    rng = random.Random(seed)

    products = product_rows(seed) + drop_rows(drop_stock)
    db.session.add_all(products)
    db.session.flush()

    users = []
    for i in range(N_USERS):
        u = User(email=username(i), name=f"{FIRST[i % len(FIRST)]} {LAST[(i // len(FIRST)) % len(LAST)]}",
                 created_at=utcnow() - timedelta(days=rng.randint(1, 900)))
        set_password(u, password_for(i, seed), hash_iters)
        if rng.random() < 0.3:
            u.loyalty_points = rng.choice([150, 320, 480, 900, 1250])
        if rng.random() < 0.45:
            u.saved_card_brand, u.saved_card_last4 = rng.choice(["Visa", "Mastercard", "Amex"]), f"{rng.randint(1000, 9999)}"
        users.append(u)
    mallory = User(email=ATTACKER_ACCOUNT[0], name="Mallory Vane", created_at=utcnow() - timedelta(days=3))
    set_password(mallory, ATTACKER_ACCOUNT[1], hash_iters)
    users.append(mallory)
    db.session.add_all(users)
    db.session.flush()

    for u in rng.sample(users[:N_USERS], 120):
        city, postcode, country = rng.choice(CITIES)
        db.session.add(Address(user_id=u.id, line1=f"{rng.randint(1, 999)} {rng.choice(LAST)} Street",
                               city=city, postcode=postcode, country=country))

    catalogue = products[:120]
    for n in range(800):
        u = rng.choice(users[:N_USERS])
        p = rng.choice(catalogue)
        qty = 1 if rng.random() < 0.85 else 2
        o = Order(number=f"K{seed % 1000:03d}{n + 1:05d}", user_id=u.id, email=u.email, total_cents=p.price_cents * qty,
                  created_at=utcnow() - timedelta(days=rng.randint(1, 700), minutes=rng.randint(0, 1439)))
        o.items.append(OrderItem(sku=p.sku, name=p.name, size=rng.choice(p.sizes) if p.sizes else "", qty=qty,
                                 price_cents=p.price_cents))
        db.session.add(o)

    ratings = {}
    for n in range(600):
        u = rng.choice(users[:N_USERS])
        p = rng.choice(catalogue)
        rating = rng.choice([5, 5, 5, 4, 4, 4, 3, 2])
        db.session.add(Review(sku=p.sku, user_id=u.id, author=u.name.split()[0], rating=rating,
                              title=rng.choice(REVIEW_TITLES), body=rng.choice(REVIEW_BODIES),
                              created_at=utcnow() - timedelta(days=rng.randint(1, 400))))
        ratings.setdefault(p.sku, []).append(rating)
    for p in catalogue:
        if p.sku in ratings:
            p.rating = sum(ratings[p.sku]) / len(ratings[p.sku])

    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    for n in range(200):
        code = "GC-" + "".join(rng.choice(alphabet) for _ in range(4)) + "-" + "".join(rng.choice(alphabet) for _ in range(4))
        db.session.add(GiftCard(code=code, balance_cents=rng.choice([1000, 2500, 5000, 10000])))

    db.session.commit()
    return {"seeded": True, "products": len(products), "users": len(users), "orders": 800, "reviews": 600, "gift_cards": 200}


def reset_state(drop_stock=50):
    """Lab reset between rounds: restore drop stock, drop lab-created rows, keep seed data.

    Lab-created rows are the ones the running store wrote: orders with a session id (seeded
    history has none), reviews and users carrying a session id in `extra`, every newsletter
    row, every decision. Order lines go first: SQLite reuses the ids of deleted orders, and
    orphaned lines would attach to the next round's orders.
    """
    for p in Product.query.filter_by(is_drop=True):
        p.stock = drop_stock
    lab_orders = [o.id for o in Order.query.filter(Order.session_id.isnot(None))]
    if lab_orders:
        OrderItem.query.filter(OrderItem.order_id.in_(lab_orders)).delete(synchronize_session=False)
        Order.query.filter(Order.id.in_(lab_orders)).delete(synchronize_session=False)
    for r in Review.query.filter(Review.created_at >= utcnow() - timedelta(days=1)):
        if (r.extra or {}).get("sid") or r.status != "published":
            db.session.delete(r)
    GiftCard.query.filter(GiftCard.redeemed_by.isnot(None)).update({"redeemed_by": None}, synchronize_session=False)
    Newsletter.query.delete()
    Decision.query.delete()
    for u in User.query.filter(User.id > N_USERS + 1):
        db.session.delete(u)
    db.session.commit()


if __name__ == "__main__":
    from demo_site.app import create_app
    app = create_app()
    with app.app_context():
        print(seed_all(app.config["LAB"].lab_seed, app.config["LAB"].drop_stock, app.config["LAB"].hash_iters,
                       reset="--reset" in sys.argv))
