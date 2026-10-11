"""
Chapter 7 — Event store shared by the demo site, training and the tools

Everything the model learns from is written here by the demo site:
  sessions   first sighting of each session cookie and its IP
  requests   one row per HTTP request (the server-side view)
  telemetry  fingerprint + behavior summaries POSTed by the page collector
             (the client-side view built in W2 Ch3 and W2 Ch4)
  logins     which session logged into which account
  accounts   seeded customer accounts with order history (a label source)
  orders     checkout attempts, the score they got and the decision

Storage: PostgreSQL from ../docker-compose.yml by default. Set
DATABASE_URL=sqlite:///ml_lab.db to run without Docker.

Timestamps are real Unix seconds. Every *duration* the features use is
divided by LAB_TIME_SCALE (see tools/labclient.py), so the simulators can
compress a shopping session of minutes into about a second.
"""

import os

from sqlalchemy import (Column, Float, Integer, MetaData, String, Table, Text,
                        create_engine, event)

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://workshop:workshop@localhost:5432/shop")
# Shared by the site, the features and the simulators. Change it and re-run
# everything: features computed at different scales are not comparable.
LAB_TIME_SCALE = float(os.environ.get("LAB_TIME_SCALE", "0.02"))

metadata = MetaData()

requests_t = Table(
    "requests", metadata,
    Column("id", Integer, primary_key=True),
    Column("sid", String(40), index=True),
    Column("ts", Float, index=True),
    Column("method", String(8)),
    Column("path", String(200)),
    Column("status", Integer),
    Column("ip", String(45)),
    Column("ua", Text),
    Column("referer", Text),
    Column("accept_language", String(200)),
    Column("sec_fetch_site", String(40)),
    Column("is_asset", Integer),
    Column("bytes_out", Integer),
)

telemetry_t = Table(
    "telemetry", metadata,
    Column("id", Integer, primary_key=True),
    Column("sid", String(40), index=True),
    Column("ts", Float, index=True),
    Column("kind", String(8)),          # 'fp' or 'beh'
    Column("payload", Text),            # JSON
    Column("fp_hash", String(64), index=True),
    Column("ip", String(45)),
)

sessions_t = Table(
    "sessions", metadata,
    Column("sid", String(40), primary_key=True),
    Column("first_ts", Float, index=True),
    Column("ip", String(45)),
    Column("ip24", String(45), index=True),
)

logins_t = Table(
    "logins", metadata,
    Column("id", Integer, primary_key=True),
    Column("sid", String(40), index=True),
    Column("ts", Float),
    Column("account", String(40)),
)

accounts_t = Table(
    "accounts", metadata,
    Column("account", String(40), primary_key=True),
    Column("orders", Integer),
    Column("age_days", Integer),
)

orders_t = Table(
    "orders", metadata,
    Column("id", Integer, primary_key=True),
    Column("sid", String(40), index=True),
    Column("ts", Float, index=True),
    Column("level", Integer),
    Column("score", Float),             # supervised model probability
    Column("anomaly", Float),           # anomaly score (level >= 3)
    Column("decision", String(12)),     # allow | block | pending
    Column("status", String(12)),       # confirmed | blocked | pending | cancelled
    Column("review_at", Float),
    Column("score_ms", Float),
)


def make_engine(url=None):
    url = url or DATABASE_URL
    if url.startswith("sqlite"):
        engine = create_engine(url, connect_args={"timeout": 30, "check_same_thread": False})

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(conn, _):
            # WAL lets the simulators write while training reads
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()
        return engine
    return create_engine(url, pool_size=20, max_overflow=20)


def seed_accounts(conn, n=400):
    """Deterministic customer base: user0000..user0399 with order history."""
    if conn.execute(accounts_t.select().limit(1)).first():
        return
    rows = []
    for i in range(n):
        # Every 3rd account is a long-standing customer with several orders
        loyal = i % 3 != 2
        rows.append({"account": f"user{i:04d}",
                     "orders": 3 + i % 9 if loyal else i % 2,
                     "age_days": 120 + i if loyal else 5 + i % 30})
    conn.execute(accounts_t.insert(), rows)


def init_db(engine):
    metadata.create_all(engine)
    with engine.begin() as conn:
        seed_accounts(conn)


def reset_db(engine):
    """Drop every event: used by `tools/checkpoint.py --reset`."""
    metadata.drop_all(engine)
    init_db(engine)
