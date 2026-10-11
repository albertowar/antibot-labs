"""Shared datastore for the W4 Ch1 demo store (the W4 starter state).

Two backends, picked by environment variables, so the lab runs dependency-free on
a laptop and in a production-shaped stack:

  * Redis -> a real server when REDIS_URL is set, otherwise in-process ``fakeredis``.
    Holds per-client request history, cluster coverage sets and rate budgets. Only
    the store touches it; the tools drive the store over HTTP.
  * SQL -> PostgreSQL when DATABASE_URL is set, otherwise a local SQLite file.
    Holds the product catalog and the append-only decision log both the store and
    the tools read.

Nothing here identifies a crawler. It is the plumbing the defenses build on.
"""

from __future__ import annotations

import os
import time
from collections import namedtuple

from flask_sqlalchemy import SQLAlchemy

# --- The decision vocabulary, shared by app, defenses, scoreboard, checkpoint ---
ALLOW = "allow"          # served
LIMIT = "limit"          # served while within budget, 429 beyond it (friction)
CHALLENGE = "challenge"  # step-up (W4 Ch3 makes this a proof-of-work gate)
BLOCK = "block"          # refused

Decision = namedtuple("Decision", "action reason")


def allow(reason=""):
    return Decision(ALLOW, reason)


def limit(reason):
    return Decision(LIMIT, reason)


def challenge(reason):
    return Decision(CHALLENGE, reason)


def block(reason):
    return Decision(BLOCK, reason)


# The identity classes the store assigns before it decides what to do.
BROWSER_LIKE = "browser-like"              # a browser User-Agent, no crawler claim
DECLARED_UNCHECKED = "declared-unchecked"  # claims a known token; nothing verified yet (L1)
DECLARED_VERIFIED = "declared-verified"    # claim confirmed by ranges or FCrDNS
IMPERSONATOR = "impersonator"              # claim checked and found false
DECLARED_UNVERIFIABLE = "declared-unverifiable"  # known token, operator publishes no proof
DECLARED_UNLISTED = "declared-unlisted"    # looks like a bot, token in no registry
UNDECLARED_CRAWLER = "undeclared-crawler"  # browser UA, crawler behaviour


def make_redis():
    """Return a Redis client, or an in-process fakeredis when no server is set."""
    url = os.environ.get("REDIS_URL")
    if url and url != "memory://":
        import redis  # lazy, so the lab installs with no server
        return redis.Redis.from_url(url, decode_responses=True)
    import fakeredis
    return fakeredis.FakeStrictRedis(decode_responses=True)


db = SQLAlchemy()


class Product(db.Model):
    __tablename__ = "products"
    sku = db.Column(db.String(16), primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(40), nullable=False)
    price = db.Column(db.Float, nullable=False)
    blurb = db.Column(db.String(255), nullable=False, default="")


class Decision_(db.Model):
    """One row per gated page request.

    ``actor`` is lab-only ground truth stamped by the traffic generators
    (``human:chrome-desktop``, ``legit:verified-googlebot``, ``attack:round2``). The
    edge strips it before any defense runs; it exists so the scoreboard can tell a
    crawler that got through from a person who got blocked.
    """

    __tablename__ = "decisions"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.Float, nullable=False, index=True)
    level = db.Column(db.Integer, nullable=False)
    actor = db.Column(db.String(48), nullable=False, index=True)
    client_ip = db.Column(db.String(45), nullable=False)
    asn_class = db.Column(db.String(16), nullable=False, default="")
    path = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(48), nullable=False, default="")
    identity = db.Column(db.String(24), nullable=False, index=True)
    purpose = db.Column(db.String(16), nullable=False, default="")
    verify_method = db.Column(db.String(12), nullable=False, default="")
    score = db.Column(db.Float, nullable=False, default=0.0)
    action = db.Column(db.String(12), nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=False, default="")
    latency_ms = db.Column(db.Float, nullable=False, default=0.0)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


def log_decision(**kwargs) -> None:
    db.session.add(Decision_(ts=time.time(), **kwargs))
    db.session.commit()


# --- Catalog seed: 120 products, deterministic ------------------------------------
_ADJ = ["Trail", "Urban", "Alpine", "Harbor", "Studio", "Field", "Night", "Summit", "Delta", "Pixel"]
_NOUN = {"shoes": ["Runner", "Loafer", "Boot", "Sandal"], "bags": ["Tote", "Pack", "Duffel", "Satchel"],
         "audio": ["Earbuds", "Speaker", "Headset", "Amp"], "home": ["Lamp", "Kettle", "Blanket", "Planter"],
         "outdoor": ["Tent", "Stove", "Bottle", "Hammock"], "kids": ["Scooter", "Puzzle", "Kite", "Crayons"]}


def seed_products():
    """Fill the catalog if it is empty. 120 SKUs p001..p120 across six categories."""
    if Product.query.count():
        return 0
    cats = list(_NOUN)
    n = 0
    for i in range(120):
        cat = cats[i % len(cats)]
        adj = _ADJ[(i // len(cats)) % len(_ADJ)]
        noun = _NOUN[cat][(i // (len(cats) * len(_ADJ))) % 4]
        price = 9.0 + ((i * 37) % 190) + 0.99
        db.session.add(Product(sku=f"p{i + 1:03d}", name=f"{adj} {noun}", category=cat, price=price,
                               blurb=f"The {adj.lower()} {noun.lower()} for everyday use."))
        n += 1
    db.session.commit()
    return n
