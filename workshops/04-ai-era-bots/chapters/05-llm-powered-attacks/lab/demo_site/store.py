"""Shared datastore for the W4 Ch5 "LLM-powered attacks" demo store.

This is the end-of-Workshop-2 store with the surfaces this chapter attacks added:
customer reviews, a challenge gate in front of registration, an HTML catalogue
page, and two LLM-backed features (a review summariser and a support assistant).

Two backends, chosen by environment variables, so the lab runs dependency-free
on a bare laptop *and* in a production-shaped stack:

  * Redis -> a real server when REDIS_URL is set, otherwise an in-process
    ``fakeredis``. Only the demo site touches Redis; attacks and the
    legitimate-traffic simulator drive the app over HTTP.
  * SQL (products, users, purchases, reviews and the append-only decision log)
    -> PostgreSQL when DATABASE_URL is set, otherwise a local SQLite file.

Nothing here is bot-detection logic. It is the plumbing the defenses build on.
"""

from __future__ import annotations

import os
import time
from collections import namedtuple

from flask_sqlalchemy import SQLAlchemy

# --- The decision vocabulary, shared by app, defenses, scoreboard, checkpoint ---

ALLOW = "allow"          # request served
CHALLENGE = "challenge"  # friction: held for moderation, step-up, puzzle served
BLOCK = "block"          # refused
INVALID = "invalid"      # bad input (not a bot verdict)

# ``reason`` is for teaching only: a real endpoint never tells a client which
# rule caught it.
Decision = namedtuple("Decision", "action score reason")


def allow(reason="", score=0.0):
    return Decision(ALLOW, score, reason)


def challenge(reason, score=0.0):
    return Decision(CHALLENGE, score, reason)


def block(reason, score=0.0):
    return Decision(BLOCK, score, reason)


# --- Redis (velocity counters, challenge tokens, canaries) ---------------------

def make_redis():
    """Return a Redis client, or an in-process fakeredis when no server is set.

    Trade-off: fakeredis keeps the lab dependency-free, but its state is per
    process and vanishes on restart. That is what we want between rounds.
    """
    url = os.environ.get("REDIS_URL")
    if url:
        import redis  # imported lazily so the lab installs with no server
        return redis.Redis.from_url(url, decode_responses=True)
    import fakeredis
    return fakeredis.FakeStrictRedis(decode_responses=True)


# --- SQL ---------------------------------------------------------------------

db = SQLAlchemy()


class Product(db.Model):
    __tablename__ = "products"
    sku = db.Column(db.String(64), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(64), nullable=False, default="catalog")
    blurb = db.Column(db.String(255), nullable=False, default="")
    # Honeypot SKUs are never shown to a person. A client that fetches one, or
    # that carries one in its harvested data, only "saw" it by reading what humans
    # cannot (Round 3).
    honeypot = db.Column(db.Boolean, default=False, nullable=False)


class User(db.Model):
    __tablename__ = "users"
    email = db.Column(db.String(255), primary_key=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.Float, nullable=False, default=time.time)
    # Lab-only label of how the account came to exist, for the scoreboard.
    origin = db.Column(db.String(32), nullable=False, default="organic")


class Purchase(db.Model):
    __tablename__ = "purchases"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    sku = db.Column(db.String(64), nullable=False, index=True)
    ts = db.Column(db.Float, nullable=False, default=time.time)


class Review(db.Model):
    """A customer review. ``published`` is the attacker's success metric in
    Rounds 1 and 4: a review that is held (challenge) or refused (block) never
    reaches the product page or the summariser."""

    __tablename__ = "reviews"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.Float, nullable=False, default=time.time)
    sku = db.Column(db.String(64), nullable=False, index=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    rating = db.Column(db.Integer, nullable=False, default=5)
    text = db.Column(db.Text, nullable=False)
    actor = db.Column(db.String(32), nullable=False, default="unknown")
    fp = db.Column(db.String(64), nullable=False, default="")
    outcome = db.Column(db.String(16), nullable=False, default=ALLOW)
    published = db.Column(db.Boolean, nullable=False, default=False)


class Decision_(db.Model):
    """One row per gated action, across all four rounds.

    ``actor`` is lab-only ground truth: the traffic generators stamp every request
    with ``X-Lab-Actor`` (human / bot) so the scoreboard can tell an attack that
    got through from a real user who got blocked. A real endpoint has no such
    oracle; it exists only to measure both sides of the arms race.
    """

    __tablename__ = "decisions"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.Float, nullable=False, index=True)
    round = db.Column(db.Integer, nullable=False, index=True)
    actor = db.Column(db.String(32), nullable=False, index=True)
    endpoint = db.Column(db.String(48), nullable=False)
    client_ip = db.Column(db.String(64), nullable=False, default="")
    net_type = db.Column(db.String(16), nullable=False, default="")
    fp = db.Column(db.String(64), nullable=False, default="")
    outcome = db.Column(db.String(16), nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=False, default="")
    score = db.Column(db.Float, nullable=False, default=0.0)
    latency_ms = db.Column(db.Float, nullable=False, default=0.0)
    # LLM cost of serving this request (0 when no model was called).
    tokens = db.Column(db.Integer, nullable=False, default=0)


def log_decision(**kwargs) -> None:
    db.session.add(Decision_(ts=time.time(), **kwargs))
    db.session.commit()
