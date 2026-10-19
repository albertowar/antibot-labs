"""
Data model of the store. Chapters add columns through the `extra` JSON fields
or their own tables in an ext module; they do not change these.

Money is stored in cents. Passwords are PBKDF2-SHA256 at a deliberately low
iteration count (see seed.py) so the lab stays fast; production uses Argon2id.
"""

from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import JSON

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(32), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(40), nullable=False, index=True)
    price_cents = db.Column(db.Integer, nullable=False)
    blurb = db.Column(db.Text, default="")
    colorway = db.Column(db.String(40), default="")
    sizes = db.Column(JSON, default=list)
    stock = db.Column(db.Integer, default=500)
    hidden = db.Column(db.Boolean, default=False)       # honeypot SKUs (W1 Ch7) never appear in listings
    is_drop = db.Column(db.Boolean, default=False)
    drop_at = db.Column(db.DateTime, nullable=True)
    max_per_account = db.Column(db.Integer, default=0)  # 0 = unlimited
    rating = db.Column(db.Float, default=0.0)
    extra = db.Column(JSON, default=dict)

    @property
    def price(self):
        return self.price_cents / 100

    @property
    def drop_open(self):
        return self.is_drop and (self.drop_at is None or self.drop_at <= utcnow())

    def to_dict(self, stock=False):
        d = {"sku": self.sku, "name": self.name, "category": self.category, "price_cents": self.price_cents,
             "price": self.price, "blurb": self.blurb, "colorway": self.colorway, "sizes": self.sizes or [],
             "rating": round(self.rating or 0, 1), "image": f"/img/{self.sku}.svg", "url": f"/product/{self.sku}",
             "is_drop": self.is_drop}
        if stock:
            d["stock"] = self.stock
        if self.is_drop:
            d["drop_at"] = self.drop_at.isoformat() + "Z" if self.drop_at else None
            d["drop_open"] = self.drop_open
            d["url"] = f"/drop/{self.sku}"
        return d


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(80), default="")
    password_salt = db.Column(db.LargeBinary(32), nullable=False)
    password_hash = db.Column(db.LargeBinary(64), nullable=False)
    loyalty_points = db.Column(db.Integer, default=0)
    saved_card_last4 = db.Column(db.String(4), nullable=True)
    saved_card_brand = db.Column(db.String(16), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)
    extra = db.Column(JSON, default=dict)
    addresses = db.relationship("Address", backref="user", lazy=True, cascade="all, delete-orphan")
    orders = db.relationship("Order", backref="user", lazy=True)

    def to_dict(self):
        return {"email": self.email, "name": self.name, "loyalty_points": self.loyalty_points,
                "saved_card": f"{self.saved_card_brand} •••• {self.saved_card_last4}" if self.saved_card_last4 else None,
                "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
                "addresses": [a.to_dict() for a in self.addresses]}


class Address(db.Model):
    __tablename__ = "addresses"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    line1 = db.Column(db.String(120))
    city = db.Column(db.String(80))
    postcode = db.Column(db.String(16))
    country = db.Column(db.String(2), default="US")

    def to_dict(self):
        return {"line1": self.line1, "city": self.city, "postcode": self.postcode, "country": self.country}


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(16), unique=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    email = db.Column(db.String(120), nullable=False)
    total_cents = db.Column(db.Integer, default=0)
    status = db.Column(db.String(16), default="paid")
    session_id = db.Column(db.String(64), nullable=True, index=True)
    actor = db.Column(db.String(64), nullable=True)      # lab ground truth, scoreboard only
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    extra = db.Column(JSON, default=dict)
    items = db.relationship("OrderItem", backref="order", lazy=True, cascade="all, delete-orphan")

    @property
    def total(self):
        return self.total_cents / 100

    def to_dict(self):
        return {"number": self.number, "email": self.email, "total_cents": self.total_cents,
                "total": self.total_cents / 100, "status": self.status,
                "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
                "items": [i.to_dict() for i in self.items]}


class OrderItem(db.Model):
    __tablename__ = "order_items"
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False, index=True)
    sku = db.Column(db.String(32), nullable=False)
    name = db.Column(db.String(120))
    size = db.Column(db.String(8), default="")
    qty = db.Column(db.Integer, default=1)
    price_cents = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {"sku": self.sku, "name": self.name, "size": self.size, "qty": self.qty, "price_cents": self.price_cents}


class Review(db.Model):
    __tablename__ = "reviews"
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(32), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    author = db.Column(db.String(80), default="")
    rating = db.Column(db.Integer, default=5)
    title = db.Column(db.String(120), default="")
    body = db.Column(db.Text, default="")
    status = db.Column(db.String(16), default="published")   # published | pending | removed
    created_at = db.Column(db.DateTime, default=utcnow)
    extra = db.Column(JSON, default=dict)

    def to_dict(self):
        return {"id": self.id, "sku": self.sku, "author": self.author, "rating": self.rating, "title": self.title,
                "body": self.body, "status": self.status,
                "created_at": self.created_at.isoformat() + "Z" if self.created_at else None}


class GiftCard(db.Model):
    __tablename__ = "gift_cards"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(16), unique=True, nullable=False, index=True)
    balance_cents = db.Column(db.Integer, default=0)
    redeemed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    def to_dict(self):
        return {"code": self.code, "balance_cents": self.balance_cents, "balance": self.balance_cents / 100}


class Newsletter(db.Model):
    __tablename__ = "newsletter"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    extra = db.Column(JSON, default=dict)


class Decision(db.Model):
    """One row per gated request: what the defenses saw and what the client got.

    `actor` is lab ground truth (from X-Lab-Actor). It exists so the scoreboard can
    tell shoppers from bots; no defense may read it (tools/smoke.py checks).
    """
    __tablename__ = "decisions"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime, default=utcnow, index=True)
    sid = db.Column(db.String(64), index=True)
    user_id = db.Column(db.Integer, nullable=True)
    actor = db.Column(db.String(64), index=True)
    phase = db.Column(db.String(32))
    method = db.Column(db.String(8))
    path = db.Column(db.String(200))
    ip = db.Column(db.String(45))
    level = db.Column(db.Integer)
    score = db.Column(db.Integer)
    action = db.Column(db.String(16))       # what the ladder decided
    enforced = db.Column(db.String(16))     # what the client got (allow if a challenge was cleared, etc.)
    outcome = db.Column(db.String(24))      # served | blocked | challenged | rate_limited | deceived | purchased | ...
    status = db.Column(db.Integer)
    signals = db.Column(db.Text, default="")
    shadow = db.Column(db.Text, default="")
    ms = db.Column(db.Float, default=0.0)
    extra = db.Column(JSON, default=dict)

    def to_dict(self):
        return {"ts": self.ts.isoformat() + "Z" if self.ts else None, "sid": self.sid, "user_id": self.user_id,
                "actor": self.actor, "phase": self.phase, "method": self.method, "path": self.path, "ip": self.ip,
                "level": self.level, "score": self.score, "action": self.action, "enforced": self.enforced,
                "outcome": self.outcome, "status": self.status, "signals": self.signals, "shadow": self.shadow,
                "ms": round(self.ms or 0, 2), "extra": self.extra or {}}
