"""
Chapter 2: the glue between the collector (demo_site/static/js/fp.js) and the layer checks.

The sign-up page carries a one-time-per-session nonce (demo_site/ext/fp.py). The collector reads
raw observations from the browser and posts them, with that nonce, to the store's telemetry sink:
POST /api/telemetry {"kind": "fp", "nonce": ..., "nav": {...}, "webgl": {...}, ...}. The ext
module checks the nonce and keeps the payload, together with the headers it arrived with, as this
session's fingerprint record. Every check below reads that record when the sign-up arrives
(phase action:register, on both POST /register and POST /api/register):

    record(ctx)                     the session's fingerprint record, or None
    signals(...)                    a layer's (points, reasons) as one pipeline Signal; the reasons go
                                    to the decision log (`extra.fp_reasons`)
    accounts_today(ctx, stable_id)  L3: source IP of every account created today from this device
    recent_cores(ctx)               L4: core components of every account created today
    remember_account(ctx, email)    called by the ext when a sign-up succeeds (and only then)
    judge(ctx)                      how every level would score this session's record (the check page)

Why a record and not the telemetry the store keeps for every kind? The store keeps only the body of
the POST. L2 compares what the page says (navigator, userAgentData) with what the network stack said
(User-Agent, Sec-CH-UA, Accept-Language), so the headers of that same request have to be kept too.

Where "accounts created today" lives: Redis, one sorted set per device (`lab:fp:acct:<stable_id>`,
scored by time) and one list of core components (`lab:fp:cores`). `POST /lab/reset` flushes both.
A per-device key is the index L3 needs: the lookup is O(log n) however many accounts exist. L4 has
no such key (it compares components, not IDs), so it scans. That difference is the cost story of
Rounds 3 and 4.
"""

import json
import time

from . import policy
from .pipeline import Signal

KEPT_HEADERS = ["User-Agent", "Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform", "Accept-Language"]
WINDOW = 24 * 3600                  # "today": the linking window
CORES_KEPT = 5000                   # L4 scans at most this many recent accounts


def record_key(ctx):
    return ctx.session.ns("fp") + "record"


def store_record(ctx, payload, headers):
    ctx.redis.set(record_key(ctx), json.dumps({"at": time.time(), "payload": payload, "headers": headers}),
                  ex=policy.FP_TTL)


def record(ctx):
    """{"payload", "headers", "at"} for this session, or None (no valid report, or it expired)."""
    if "fp" not in ctx.attrs:
        raw = ctx.redis.get(record_key(ctx))
        ctx.attrs["fp"] = json.loads(raw) if raw else None
    return ctx.attrs["fp"]


class Headers:
    """`.get(name, default)` over a stored header dict, case-insensitive (what the L2 check expects)."""

    def __init__(self, stored):
        self.stored = {k.lower(): v for k, v in (stored or {}).items()}

    def get(self, name, default=None):
        return self.stored.get(name.lower(), default)


def signals(tag, name, points, reasons, ctx):
    """One Signal for a layer's score. Reasons are tagged ("[L1] ...") and go to the decision log."""
    if not points and not reasons:
        return []
    ctx.notes.setdefault("fp_reasons", []).extend(f"[{tag}] {r}" for r in reasons)
    return [Signal("fp", name if points else "noted", points, "; ".join(reasons)[:300])]


# --- "accounts created today" (L3 and L4) ----------------------------------------------------

def _acct_key(stable_id):
    return f"lab:fp:acct:{stable_id}"


def accounts_today(ctx, stable_id):
    """The source IP of every account created in the last 24 hours with this stable_id (one entry per account)."""
    now = time.time()
    members = ctx.redis.zrangebyscore(_acct_key(stable_id), now - WINDOW, "+inf")
    return [m.split("|", 1)[0] for m in members]


def recent_cores(ctx):
    """Core components of every account created in the last 24 hours (newest last)."""
    cutoff = time.time() - WINDOW
    rows = (json.loads(r) for r in ctx.redis.lrange("lab:fp:cores", -CORES_KEPT, -1))
    return [row["core"] for row in rows if row["t"] > cutoff]


def remember_account(ctx, email):
    """A sign-up succeeded: remember which device it came from. Called at every level, so a level
    switched on later sees the accounts created before it."""
    from . import stable_id as ids                 # through the module: defenses/ is hot-reloaded
    rec = record(ctx)
    if rec is None:
        return
    fp, now = rec["payload"], time.time()
    ctx.redis.zadd(_acct_key(ids.stable_id(fp)), {f"{ctx.ip}|{email}": now})
    ctx.redis.expire(_acct_key(ids.stable_id(fp)), WINDOW + 60)
    ctx.redis.rpush("lab:fp:cores", json.dumps({"t": now, "core": ids.core_components(fp)}))
    ctx.redis.ltrim("lab:fp:cores", -CORES_KEPT, -1)


# --- how every level judges a record (the /lab/fp/me page and the checkpoint's own checks) ----

def judge(ctx):
    """
    {level: {"score", "verdict", "reasons"}} for levels 1..4, cumulative, using the session's record
    and the store's current account history. Read-only: nothing is created or noted.
    """
    from . import fp_gate, fuzzy_cluster, lie_detector, linking, render_stack
    rec = record(ctx)
    layers = [(1, "L1", fp_gate), (1, "L1", render_stack), (2, "L2", lie_detector),
              (3, "L3", linking), (4, "L4", fuzzy_cluster)]
    out, score, reasons = {}, 0, []
    for level in range(1, 5):
        for min_level, tag, module in layers:
            if min_level == level and (rec is not None or module is fp_gate):
                points, why = module.evaluate(ctx)
                score += points
                reasons.extend(f"[{tag}] {r}" for r in why)
        out[level] = {"score": min(100, score), "verdict": policy.decide(min(100, score), [], level),
                      "reasons": list(reasons)}
    return out
