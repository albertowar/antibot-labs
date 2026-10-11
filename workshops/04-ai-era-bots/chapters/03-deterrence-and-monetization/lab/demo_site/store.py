"""Shared datastore for the W4 Ch3 "deterrence & monetization" demo store.

The catalogue is the asset every AI crawler in this chapter wants: 300 products
with names, prices and descriptions. The store serves it the way a real shop does,
through HTML listings and product pages, a search box, a JSON API and a sitemap.
Round 4 turns on the lesson that *all* of those are content carriers.

Two backends, chosen by environment variables, so the lab runs dependency-free on
a bare laptop *and* in a production-shaped stack:

  * Redis -> a real server when REDIS_URL is set, otherwise an in-process
    ``fakeredis``. Only the demo site touches Redis (maze tags, robots violations,
    the pay-per-crawl ledger), so a per-process fake is enough.
  * SQL (catalogue and the append-only decision log) -> PostgreSQL when
    DATABASE_URL is set, otherwise a local SQLite file. Both the app and the tools
    read the decision log, so it has to be a shared on-disk store.

Nothing here is crawler-governance logic. It is the plumbing the defenses build on.
"""

from __future__ import annotations

import os
import time
from collections import namedtuple

from flask_sqlalchemy import SQLAlchemy

# --- The decision vocabulary, shared by app, defenses, scoreboard, checkpoint ---

ALLOW = "allow"        # served, free
BLOCK = "block"        # refused (403)
MAZE = "maze"          # served a decoy maze page instead of content
PAYWALL = "paywall"    # 402 Payment Required with a price, nothing served
CHARGED = "charged"    # served, and a crawl fee was booked to the ledger

# A defense returns one of these. ``reason`` is for teaching only: a real
# endpoint never tells a client which rule caught it. ``charged`` is the USD
# amount booked for this response (Round 4), 0.0 everywhere else.
Decision = namedtuple("Decision", "action score reason charged", defaults=(0.0,))


def allow(reason="", score=0.0):
    return Decision(ALLOW, score, reason)


def block(reason, score=0.0):
    return Decision(BLOCK, score, reason)


def paywall(reason, price):
    return Decision(PAYWALL, 0.0, reason, 0.0 if price is None else float(price))


def charged(reason, price):
    return Decision(CHARGED, 0.0, reason, float(price))


# --- Redis (maze tags, violation counters, crawl ledger) -----------------------

def make_redis():
    """Return a Redis client, or an in-process fakeredis when no server is set.

    Trade-off: fakeredis keeps the lab dependency-free, but its state is per
    process and vanishes on restart. Between rounds that is what we want; the
    attack scripts and the legitimate-traffic simulator drive the app over HTTP
    and never need Redis themselves.
    """
    url = os.environ.get("REDIS_URL")
    if url:
        import redis  # imported lazily so the lab installs with no server
        return redis.Redis.from_url(url, decode_responses=True)
    import fakeredis
    return fakeredis.FakeStrictRedis(decode_responses=True)


# --- SQL (catalogue and the append-only decision log) --------------------------

db = SQLAlchemy()


class Product(db.Model):
    __tablename__ = "products"
    sku = db.Column(db.String(16), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=False)


class Decision_(db.Model):
    """One row per request the store decided on.

    ``actor`` is lab-only ground truth: the traffic generators stamp every request
    with ``X-Lab-Actor`` (human / prefetch / reader / search / bot) so the
    scoreboard can tell a crawler that got through from a real user who got
    blocked, charged or mazed. A real endpoint has no such oracle; it exists only
    to measure both sides of the arms race.

    ``skus`` lists the product records this response disclosed (one for a product
    page, up to 20 for a listing or API page, up to 50 for a search). Catalogue
    *coverage* -- the share of the 300 products a crawler got -- is the attacker's
    success metric in every round, and it is computed from this column.
    """

    __tablename__ = "decisions"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.Float, nullable=False, index=True)
    level = db.Column(db.Integer, nullable=False, index=True)   # DEFENSE_LEVEL
    actor = db.Column(db.String(32), nullable=False, index=True)
    path = db.Column(db.String(255), nullable=False)
    client_ip = db.Column(db.String(64), nullable=False, default="")
    ua_class = db.Column(db.String(32), nullable=False, default="")
    operator = db.Column(db.String(64), nullable=False, default="")
    verified = db.Column(db.Boolean, nullable=False, default=False)
    outcome = db.Column(db.String(16), nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=False, default="")
    charged = db.Column(db.Float, nullable=False, default=0.0)
    skus = db.Column(db.Text, nullable=False, default="")
    latency_ms = db.Column(db.Float, nullable=False, default=0.0)


def log_decision(**kwargs) -> None:
    db.session.add(Decision_(ts=time.time(), **kwargs))
    db.session.commit()
