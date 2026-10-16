"""
W4 Ch9 Capstone — mandates: the account holder's one-purchase authorisation (GIVEN)

A mandate is how a verified agent is allowed to buy: the ACCOUNT HOLDER grants
it (from their own session, never the agent), naming the operator, one sku and
a short expiry; the agent presents its id at checkout and it is spent on use.

The table is the defense's own state, on its own engine over the store's
DATABASE_URL (contract §4.2: an ext or check that writes SQL per request never
borrows the app's pool). demo_site/ext/capstone_store.py owns the grant route
and clears the table on /lab/reset.
"""

import os
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, create_engine, select

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DB = f"sqlite:///{os.path.join(LAB, 'instance', 'shop.db')}"

metadata = MetaData()

mandates_t = Table(
    "cap_mandates", metadata,
    Column("id", String(16), primary_key=True),
    Column("user_id", Integer, index=True),
    Column("operator", String(120)),
    Column("sku", String(32)),
    Column("max_qty", Integer, default=1),
    Column("created_at", DateTime),
    Column("expires_at", DateTime),
    Column("used_at", DateTime, nullable=True),
)

_engine = None


class Mandate:
    """Attribute view over a row (agent_governance reads .user_id, .operator, ...)."""

    def __init__(self, row):
        for k, v in row.items():
            setattr(self, k, v)
        for col in ("created_at", "expires_at", "used_at"):
            v = getattr(self, col, None)
            if v is not None and v.tzinfo is None:
                setattr(self, col, v.replace(tzinfo=timezone.utc))


def engine():
    global _engine
    if _engine is None:
        url = os.environ.get("DATABASE_URL", DEFAULT_DB)
        if url.startswith("sqlite"):
            _engine = create_engine(url, connect_args={"timeout": 30, "check_same_thread": False})
        else:
            _engine = create_engine(url, pool_size=5, max_overflow=5)
        metadata.create_all(_engine)
    return _engine


def grant(user_id, operator, sku, ttl_min=15):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    row = {"id": secrets.token_hex(8), "user_id": user_id, "operator": operator, "sku": sku,
           "max_qty": 1, "created_at": now, "expires_at": now + timedelta(minutes=ttl_min),
           "used_at": None}
    with engine().begin() as conn:
        conn.execute(mandates_t.insert().values(**row))
    return Mandate(row)


def get(mandate_id):
    with engine().connect() as conn:
        row = conn.execute(select(mandates_t).where(mandates_t.c.id == str(mandate_id))).mappings().first()
    return Mandate(dict(row)) if row else None


def for_user(user_id):
    with engine().connect() as conn:
        rows = conn.execute(select(mandates_t).where(mandates_t.c.user_id == user_id)
                            .order_by(mandates_t.c.created_at.desc())).mappings().all()
    return [Mandate(dict(r)) for r in rows]


def spend(mandate_id):
    with engine().begin() as conn:
        conn.execute(mandates_t.update().where(mandates_t.c.id == str(mandate_id))
                     .values(used_at=datetime.now(timezone.utc).replace(tzinfo=None)))


def clear():
    with engine().begin() as conn:
        conn.execute(mandates_t.delete())


def as_json(m):
    iso = lambda d: d.isoformat(timespec="seconds") if d else None  # noqa: E731
    return {"id": m.id, "operator": m.operator, "sku": m.sku, "max_qty": m.max_qty,
            "expires_at": iso(m.expires_at), "used_at": iso(m.used_at)}
