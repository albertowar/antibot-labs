"""
W4 Chapter 7 — Event store shared by the demo site, the triage pipeline and the tools

The demo site writes everything the LLM analyst will later read:
  sessions   first sighting of each session cookie, its IP and the lab run tag
  requests   one row per HTTP request: path, status, and every header the
             client chose to send (User-Agent, Referer, Accept-Language)
  logins     which session logged into which account
  accounts   seeded customer accounts with order history (the gate's legit cohort)
  orders     checkout attempts and what the rule engine decided
  verdicts   what the triage pipeline (heuristic or LLM) said about a session
  rule_hits  rules that matched at checkout, in shadow or enforce mode

Storage: SQLite by default (DATABASE_URL=sqlite:///llm_lab.db, run every lab
command from lab/). PostgreSQL from ../docker-compose.yml is optional.

Client-controlled columns are Text, not String(200): the Round 3 flood sends
multi-kilobyte headers, and a column that truncates them would hide the
attack on SQLite and crash on PostgreSQL. The site caps each stored value at
MAX_FIELD_BYTES so the database itself is not the resource the flood eats.

Timestamps are real Unix seconds. Every *duration* the session summary uses
is divided by LAB_TIME_SCALE (see tools/labclient.py), so the simulators can
compress a shopping session of minutes into about a second.
"""

import os

from sqlalchemy import (Column, Float, Integer, MetaData, String, Table, Text,
                        create_engine, event)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///llm_lab.db")
# Shared by the site, the summaries and the simulators. Change it and re-run
# everything: durations measured at different scales are not comparable.
LAB_TIME_SCALE = float(os.environ.get("LAB_TIME_SCALE", "0.02"))
MAX_FIELD_BYTES = 8192

metadata = MetaData()

requests_t = Table(
    "requests", metadata,
    Column("id", Integer, primary_key=True),
    Column("sid", String(40), index=True),
    Column("ts", Float, index=True),
    Column("method", String(8)),
    Column("path", Text),
    Column("status", Integer),
    Column("ip", String(45)),
    Column("ua", Text),
    Column("referer", Text),
    Column("accept_language", Text),
    Column("is_asset", Integer),
    Column("bytes_out", Integer),
)

sessions_t = Table(
    "sessions", metadata,
    Column("sid", String(40), primary_key=True),
    Column("first_ts", Float, index=True),
    Column("ip", String(45)),
    Column("ip24", String(45), index=True),
    Column("run", String(60), index=True),   # lab bookkeeping: which script sent it
)

logins_t = Table(
    "logins", metadata,
    Column("id", Integer, primary_key=True),
    Column("sid", String(40), index=True),
    Column("ts", Float),
    Column("account", Text),
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
    Column("decision", String(12)),     # allow | block
    Column("status", String(12)),       # confirmed | blocked
    Column("rule_id", String(20)),
    Column("rules_ms", Float),
)

verdicts_t = Table(
    "verdicts", metadata,
    Column("id", Integer, primary_key=True),
    Column("run_id", String(60), index=True),   # which triage run produced it
    Column("tag", String(40)),                  # free label, e.g. "r1-raw", "r2-hardened"
    Column("sid", String(40), index=True),
    Column("ts", Float),
    Column("backend", String(12)),              # heuristic | mock | ollama
    Column("model", String(60)),
    Column("mode", String(12)),                 # session | cluster | starved
    Column("label", String(8)),                 # human | bot | unsure
    Column("confidence", Float),
    Column("reasons", Text),                    # JSON list
    Column("proposed_rule", Text),              # JSON or null (display only, never enforced)
    Column("valid", Integer),
    Column("flags", Text),                      # JSON list of validator / sanitizer flags
    Column("prompt_tokens", Integer),
    Column("completion_tokens", Integer),
    Column("est", Integer),                     # 1 = token counts are chars/4 estimates
    Column("latency_ms", Float),
    Column("cluster_id", String(40)),
)

rule_hits_t = Table(
    "rule_hits", metadata,
    Column("id", Integer, primary_key=True),
    Column("ts", Float),
    Column("sid", String(40), index=True),
    Column("rule_id", String(20)),
    Column("mode", String(8)),                  # shadow | enforce
)


def make_engine(url=None):
    url = url or DATABASE_URL
    if url.startswith("sqlite"):
        engine = create_engine(url, connect_args={"timeout": 30, "check_same_thread": False})

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(conn, _):
            # WAL lets the simulators write while triage and the gate read
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
        # Every 3rd account is new; the rest are long-standing customers
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
