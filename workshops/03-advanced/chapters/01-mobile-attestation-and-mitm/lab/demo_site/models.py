"""
W3 Ch1 — Demo store data model (mobile store)

    User      customer accounts; known_devices holds the attested device ids
              that have logged in before (used by the Round 4 step-up).
    Order     one row per pair sold through the mobile app.
    Decision  every scored mobile action: the score, the outcome, the reasons
              and the feature vector. Layers switched off still log here
              (shadow mode), so you can see what a layer *would* have done.

This is the W2 Ch9 model, trimmed to what the mobile chapter uses. The store
defaults to SQLite so the lab runs with no Docker; set DATABASE_URL to use
PostgreSQL instead.
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
    address = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class Decision(db.Model):
    __tablename__ = "decisions"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    sid = db.Column(db.String(64), index=True)
    user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(20), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    outcome = db.Column(db.String(20), nullable=False)
    reasons = db.Column(db.JSON, default=list)
    shadow = db.Column(db.JSON, default=dict)
    features = db.Column(db.JSON, default=dict)
    score_ms = db.Column(db.Float)
