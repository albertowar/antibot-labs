"""Agent mandates: a scoped, time-boxed, single-use approval from the account holder. (GIVEN storage.)

A mandate says: "operator X may buy SKU Y for me, once, before time T". It is modelled on AP2's
intent / cart mandates and the card networks' agentic tokens (2025-2026). The validation rules are
the Round 4 exercise (defenses/checkout_gate.py); this module only stores and reads them.

Mandates are granted by people, through the account holder's own session
(`POST /api/account/mandates`, demo_site/ext/agents.py), and live in Redis under `lab:mandate:`.
"""

import json
import secrets
import time
from datetime import datetime, timezone

PREFIX = "lab:mandate:"
TTL_MAX_MIN = 60


def grant(redis, user_id, operator, sku, ttl_min=15, now=None):
    now = time.time() if now is None else now
    ttl_min = max(1, min(int(ttl_min or 15), TTL_MAX_MIN))
    m = {"id": secrets.token_hex(8), "user_id": user_id, "operator": operator.strip().lower(), "sku": sku,
         "max_qty": 1, "created_at": now, "expires_at": now + ttl_min * 60, "used_at": None}
    redis.set(PREFIX + m["id"], json.dumps(m), ex=ttl_min * 60 + 86400)
    redis.rpush(f"{PREFIX}user:{user_id}", m["id"])
    return m


def get(redis, mandate_id):
    raw = redis.get(PREFIX + str(mandate_id)) if mandate_id else None
    return json.loads(raw) if raw else None


def consume(redis, mandate_id, now=None):
    """Mark a mandate used. Single use: the order that spends it is the last one it can pay for."""
    m = get(redis, mandate_id)
    if m is not None:
        m["used_at"] = time.time() if now is None else now
        redis.set(PREFIX + m["id"], json.dumps(m), keepttl=True)
    return m


def for_user(redis, user_id):
    out = [get(redis, mid) for mid in redis.lrange(f"{PREFIX}user:{user_id}", 0, -1)]
    return [m for m in out if m]


def public(m):
    """The JSON shape the API returns (ISO timestamps)."""
    def iso(t):
        return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec="seconds") if t else None
    return {"id": m["id"], "operator": m["operator"], "sku": m["sku"], "max_qty": m["max_qty"],
            "expires_at": iso(m["expires_at"]), "used_at": iso(m["used_at"])}
