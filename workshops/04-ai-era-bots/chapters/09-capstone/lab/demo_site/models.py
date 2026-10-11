"""
W4 Ch9 Capstone — demo store data model (SQLite by default, PostgreSQL via DATABASE_URL)

    Product   the catalogue the crawlers want (120 items), the limited drop the
              agents want, and three honeypot SKUs nobody is ever shown.
    User      customer accounts (synthetic). known_devices holds device cookies
              that have checked out before.
    Order     one row per unit sold.
    Mandate   a purchase authorisation the account holder grants to an agent
              operator (W4 Ch4 Round 4).
    Review    customer reviews; `published` is the injector's success metric.
    Decision  every governed request or action: score, outcome, reasons, the
              principal, the W4 Ch8 signal row, and the governance columns the
              scoreboard needs (challenge kind, non-visual, decoy served, charged).

X-Lab-Actor is recorded in Decision.actor for measurement only. No defense reads it.
"""

from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc)


class Product(db.Model):
    __tablename__ = "products"
    sku = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(60), nullable=False, default="catalog")
    description = db.Column(db.Text, nullable=False, default="")
    drop = db.Column(db.Boolean, default=False, nullable=False)
    stock = db.Column(db.Integer, default=10_000, nullable=False)
    honeypot = db.Column(db.Boolean, default=False, nullable=False)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(300), nullable=False)
    address = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    known_devices = db.Column(db.JSON, default=list, nullable=False)


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    sku = db.Column(db.String(50), nullable=False)
    qty = db.Column(db.Integer, default=1, nullable=False)
    address = db.Column(db.String(300), nullable=False)
    placed_by = db.Column(db.String(40), default="human")
    operator = db.Column(db.String(120), nullable=True)
    mandate_id = db.Column(db.String(40), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class Mandate(db.Model):
    __tablename__ = "mandates"
    id = db.Column(db.String(40), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    operator = db.Column(db.String(120), nullable=False)
    sku = db.Column(db.String(50), nullable=False)
    max_qty = db.Column(db.Integer, default=1, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class Review(db.Model):
    __tablename__ = "reviews"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    sku = db.Column(db.String(50), nullable=False, index=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    rating = db.Column(db.Integer, default=5, nullable=False)
    text = db.Column(db.Text, nullable=False)
    actor = db.Column(db.String(40), default="unknown")
    outcome = db.Column(db.String(16), default="allow", nullable=False)
    published = db.Column(db.Boolean, default=False, nullable=False)


class Decision(db.Model):
    __tablename__ = "decisions"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    sid = db.Column(db.String(64), index=True)
    user_id = db.Column(db.Integer, nullable=True)
    actor = db.Column(db.String(40), default="unknown", index=True)   # X-Lab-Actor, measurement only
    action = db.Column(db.String(20), nullable=False)                 # content | checkout | login | register | review | llm | mandate | confirm
    path = db.Column(db.String(120), default="")
    level = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    enforced = db.Column(db.Boolean, default=True, nullable=False)     # False = shadow verdict (level too low)
    principal = db.Column(db.String(30), default="human")
    operator = db.Column(db.String(120), nullable=True)
    client = db.Column(db.String(30), nullable=True)                  # browser | local_agent | cloud_agent | assistive_agent
    egress_kind = db.Column(db.String(20), nullable=True)
    signals = db.Column(db.JSON, default=list)
    reasons = db.Column(db.JSON, default=list)
    shadow = db.Column(db.JSON, default=dict)
    features = db.Column(db.JSON, default=dict)
    challenge_kind = db.Column(db.String(20), nullable=True)
    non_visual = db.Column(db.Boolean, nullable=True)
    decoy_served = db.Column(db.Boolean, default=False, nullable=False)
    charged = db.Column(db.Float, default=0.0, nullable=False)
    score_ms = db.Column(db.Float)
