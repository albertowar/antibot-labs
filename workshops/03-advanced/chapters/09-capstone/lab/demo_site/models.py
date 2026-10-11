"""
Chapter 9 — Demo store data model (PostgreSQL via SQLAlchemy)

    User      customer accounts; known_devices holds device-cookie ids that
              have logged in before (used by the Round 4 step-up)
    Order     one row per pair sold
    Decision  every scored action (buy, login, register): the score, the
              outcome, the reasons and the feature vector. This table is your
              training data in Round 3, so it records what *every* layer
              thought, including layers that were switched off (shadow mode).
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
