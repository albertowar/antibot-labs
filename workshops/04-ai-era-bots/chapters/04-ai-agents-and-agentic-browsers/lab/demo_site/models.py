"""
W4 Ch4 — Demo store data model (SQLite by default, PostgreSQL via DATABASE_URL)

    User      customer accounts (synthetic). known_devices holds the device
              cookie ids that have checked out before.
    Order     one row per unit sold.
    Mandate   a purchase authorisation the account holder grants to an agent
              operator: who may buy what, how many, until when (Round 4).
    Decision  every scored checkout, login or registration: score, outcome,
              reasons, the principal classification, and the W2 layers'
              shadow score. The scoreboard and checkpoint read this table.

The X-Lab-Actor header (human / agent-honest / agent / fleet …) is recorded
in Decision.actor for *measurement only*. No defense reads it.
"""

from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc)


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
    placed_by = db.Column(db.String(40), default="human")   # human | declared_agent | verified_agent
    operator = db.Column(db.String(120), nullable=True)
    mandate_id = db.Column(db.String(40), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class Mandate(db.Model):
    __tablename__ = "mandates"
    id = db.Column(db.String(40), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    operator = db.Column(db.String(120), nullable=False)    # Signature-Agent host the mandate is for
    sku = db.Column(db.String(50), nullable=False)
    max_qty = db.Column(db.Integer, default=1, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class Decision(db.Model):
    __tablename__ = "decisions"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    sid = db.Column(db.String(64), index=True)
    user_id = db.Column(db.Integer, nullable=True)
    actor = db.Column(db.String(40), default="unknown", index=True)   # X-Lab-Actor, measurement only
    action = db.Column(db.String(20), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    principal = db.Column(db.String(30), default="human")    # human | declared_agent | verified_agent | suspected_agent
    operator = db.Column(db.String(120), nullable=True)
    reasons = db.Column(db.JSON, default=list)
    shadow = db.Column(db.JSON, default=dict)
    features = db.Column(db.JSON, default=dict)
    score_ms = db.Column(db.Float)
