"""Shared datastore for the W3 Ch6 "specialized attack scenarios" demo store.

This is the end-of-W2 store, extended for five attacker economies: a login
(credential stuffing), a limited sneaker drop with a cart/checkout funnel
(scalping), a product catalogue (adversarial scraping), a registration form
(fake-account farming) and an ad click tracker (click fraud).

Two backends, chosen by environment variables, so the lab runs dependency-free
on a bare laptop *and* in a production-shaped stack:

  * Redis -> a real server when REDIS_URL is set, otherwise an in-process
    ``fakeredis``. The demo site is the only process that touches Redis, so the
    fake (which lives only in this process) is enough; the attack scripts and the
    legitimate-traffic simulator drive the app over HTTP and never touch Redis.
  * SQL (products, users, orders, and the append-only decision log) -> PostgreSQL
    when DATABASE_URL is set, otherwise a local SQLite file. Both the app and the
    tools read the decision log, so it has to be a shared on-disk store.

Nothing here is bot-detection logic. It is the plumbing the defenses build on.
"""

from __future__ import annotations

import os
import time
from collections import namedtuple

from flask_sqlalchemy import SQLAlchemy

# --- The decision vocabulary, shared by app, defenses, scoreboard, checkpoint ---

# A defense returns one of these actions. The store maps it to an HTTP response
# and logs it, so both the attacker's success and the cost to real users show up.
ALLOW = "allow"          # request served
CHALLENGE = "challenge"  # interactive step-up / friction (reset, CAPTCHA, queue)
BLOCK = "block"          # refused
INVALID = "invalid"      # bad credentials / bad input (not a bot verdict)

# A defense module returns one of these. ``reason`` is for teaching only: a real
# endpoint never tells a client which rule caught it.
Decision = namedtuple("Decision", "action score reason")


def allow(reason="", score=0.0):
    return Decision(ALLOW, score, reason)


def challenge(reason, score=0.0):
    return Decision(CHALLENGE, score, reason)


def block(reason, score=0.0):
    return Decision(BLOCK, score, reason)


# --- Redis (velocity counters, funnel state, inventory, cluster sets) -----------

def make_redis():
    """Return a Redis client, or an in-process fakeredis when no server is set.

    Trade-off: fakeredis keeps the lab dependency-free, but its state is per
    process and vanishes on restart. That is what we want between rounds, and the
    attack/legit tooling never needs Redis because it drives the app over HTTP.
    """
    url = os.environ.get("REDIS_URL")
    if url:
        import redis  # imported lazily so the lab installs with no server
        return redis.Redis.from_url(url, decode_responses=True)
    import fakeredis
    return fakeredis.FakeStrictRedis(decode_responses=True)


# --- SQL (catalogue, users, orders, and the append-only decision log) -----------

db = SQLAlchemy()


class Product(db.Model):
    __tablename__ = "products"
    sku = db.Column(db.String(64), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(64), nullable=False, default="catalog")
    # Honeypot SKUs are never linked from the navigation. A client that fetches
    # one only found it by enumerating, which is a scraper tell (Round 3).
    honeypot = db.Column(db.Boolean, default=False, nullable=False)
    # The limited drop has finite stock; everything else is always in stock.
    drop = db.Column(db.Boolean, default=False, nullable=False)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(32), primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    # Whether this account's password is in the local breach corpus. Seeded so the
    # demo need not hash-and-range-check on every read; the login path still does
    # the k-anonymity check against the password the client actually submits.
    password_breached = db.Column(db.Boolean, default=False, nullable=False)


class Decision_(db.Model):
    """One row per gated action, across all five rounds.

    ``actor`` is lab-only ground truth: the traffic generators stamp every request
    with ``X-Lab-Actor`` (human / bot / bot2) so the scoreboard can tell an attack
    that got through from a real user who got blocked. A real endpoint has no such
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


def log_decision(**kwargs) -> None:
    db.session.add(Decision_(ts=time.time(), **kwargs))
    db.session.commit()
