"""SQLAlchemy models for the W3 Ch2 API demo store.

The store is the end-of-Workshop-2 sneaker shop ("Lab Runner 9"), now reached
through a versioned REST API, a GraphQL endpoint and a WebSocket feed instead of
only HTML pages. The schema is deliberately small; the point of the chapter is
the *API surface*, not the data model.

``Decision`` is the append-only log every tool reads. ``actor`` is lab-only
ground truth: attack scripts and the legitimate simulator stamp every request
with ``X-Lab-Actor`` so the scoreboard can separate a blocked bot from a blocked
real user. A production API has no such oracle; it is here only to measure both
sides of the arms race.
"""

from __future__ import annotations

import time

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def now() -> float:
    return time.time()


class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)
    inventory = db.Column(db.Integer, nullable=False, default=0)
    # Internal SKUs that are never linked from the UI. A catalogue walker that
    # enumerates /api/v2/products/<id> finds them anyway — that is the point of
    # the Round 1 enumeration attack.
    hidden = db.Column(db.Boolean, nullable=False, default=False)

    def public(self) -> dict:
        return {"id": self.id, "sku": self.sku, "name": self.name,
                "price": self.price, "inventory": self.inventory}


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(32), primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    # Per-user HMAC signing secret handed to the first-party mobile client at
    # login. Round 5 binds protected requests to it; a stolen bearer token
    # without the secret cannot forge a valid signature.
    api_secret = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.Float, nullable=False, default=now)


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(32), db.ForeignKey("users.id"), nullable=False, index=True)
    sku = db.Column(db.String(64), nullable=False)
    ts = db.Column(db.Float, nullable=False, default=now)


class Decision(db.Model):
    """One row per scored request, across all three API surfaces."""

    __tablename__ = "decisions"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.Float, nullable=False, index=True)
    actor = db.Column(db.String(64), nullable=False, default="", index=True)
    client_ip = db.Column(db.String(64), nullable=False, default="")
    level = db.Column(db.Integer, nullable=False, default=0)
    surface = db.Column(db.String(16), nullable=False, default="")  # rest | graphql | ws
    action = db.Column(db.String(48), nullable=False, default="")
    score = db.Column(db.Float, nullable=False, default=0.0)
    outcome = db.Column(db.String(16), nullable=False, default="allow", index=True)
    reasons = db.Column(db.JSON, nullable=False, default=list)
    shadow = db.Column(db.JSON, nullable=False, default=dict)
    cost_ms = db.Column(db.Float, nullable=False, default=0.0)

    def as_dict(self) -> dict:
        return {
            "ts": self.ts, "actor": self.actor, "client_ip": self.client_ip,
            "level": self.level, "surface": self.surface, "action": self.action,
            "score": self.score, "outcome": self.outcome, "reasons": self.reasons,
            "shadow": self.shadow, "cost_ms": self.cost_ms,
        }
