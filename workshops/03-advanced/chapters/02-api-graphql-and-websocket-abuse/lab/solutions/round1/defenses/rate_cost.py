"""
Round 1 (level 1) - cost-aware rate limiting for the REST API.

Counting requests is the wrong unit for an API. One ``GET /api/v2/reviews?limit=200`` costs a backend far more
than one ``GET /api/products/p017``, yet a request-counting limiter scores them the same. A bot that pulls the
review corpus in oversized pages, or enumerates ``/api/products/<sku>`` in order, drains the data while staying
under a naive per-minute cap.

Two complementary signals, both keyed on the caller (the bearer subject if there is one, else the rented
source address), over a short sliding window:

  * a **cost budget**: each request spends cost proportional to how much data it asks for, and a caller that
    overspends the budget is told to slow down (429). A page bigger than MAX_PER_PAGE is refused outright.
  * an **enumeration penalty**: a caller that pulls many *sequential* product ids in the window is walking the
    catalogue by id, which no human browsing session does. This catches the slow walker that stays under the
    cost budget.

The bookkeeping (classify, request_cost, _spend, _record_id, _looks_sequential) ships done. Your job is
``score_rest``: decide what a call is worth. The wrapper ``_check`` below turns your (points, reasons) into
the gate's answer: a reason that starts with "cost budget" is a 429 with Retry-After, any other points are a
block-band signal.

False positives to keep in mind (see the chapter's "where this stops" section): shared egress addresses (CGNAT,
a corporate NAT, a mobile carrier) concentrate many real users onto one key, so key on an authenticated subject
wherever you can and keep the address budget generous. API gateways and server-side rendering fan out to your
API legitimately; allowlist them rather than tuning the budget down.
"""

import math
import re
import time

from .pipeline import Check, Signal, Verdict

WINDOW_S = 10.0          # sliding window
COST_BUDGET = 40         # cost units per key per window before we slow the caller down
MAX_PER_PAGE = 50        # a page larger than this is refused
ENUM_THRESHOLD = 8       # distinct ids in the window before we look at their order
ENUM_SEQ_FRACTION = 0.7  # fraction of consecutive ids that marks a walk
PAGE_SIZE = 24           # the canonical catalogue page (/api/products, /api/search)
BLOCK_POINTS = 80        # policy blocks at >= 75

SKU = re.compile(r"^p(\d{3})$")


def request_cost(is_list, per_page):
    """Cost a request spends against the budget: a list of N items costs ~N/10, a detail costs 1."""
    if is_list:
        return max(1, math.ceil(min(per_page, 500) / 10))
    return 1


def _spend(redis, key, weight):
    """Add ``weight`` cost units to the window and return the window total."""
    nowf = time.time()
    rkey = f"lab:ch2:cost:{key}"
    members = {f"{nowf:.6f}:{i}": nowf for i in range(max(1, weight))}
    pipe = redis.pipeline()
    pipe.zremrangebyscore(rkey, 0, nowf - WINDOW_S)
    pipe.zadd(rkey, members)
    pipe.zcard(rkey)
    pipe.expire(rkey, int(WINDOW_S) + 1)
    _, _, total, _ = pipe.execute()
    return int(total)


def _record_id(redis, key, product_id):
    """Record a detail-page id hit and return the distinct ids seen in the window."""
    nowf = time.time()
    rkey = f"lab:ch2:enum:{key}"
    pipe = redis.pipeline()
    pipe.zremrangebyscore(rkey, 0, nowf - WINDOW_S)
    pipe.zadd(rkey, {str(product_id): nowf})
    pipe.zrange(rkey, 0, -1)
    pipe.expire(rkey, int(WINDOW_S) + 1)
    _, _, ids, _ = pipe.execute()
    return sorted(int(x) for x in ids)


def _looks_sequential(ids):
    """True when the distinct ids form a near-contiguous walk, like 1,2,3,4,..."""
    if len(ids) < ENUM_THRESHOLD:
        return False
    consecutive = sum(1 for a, b in zip(ids, ids[1:]) if b - a == 1)
    return consecutive / (len(ids) - 1) >= ENUM_SEQ_FRACTION


def classify(ctx):
    """What kind of REST call is this? None means the request is not metered (pages, GraphQL, login)."""
    p = ctx.path
    if p in ("/api/products", "/api/search"):
        return {"is_list": True, "is_detail": False, "per_page": PAGE_SIZE}
    if p == "/api/v2/reviews":
        try:
            n = int(ctx.args.get("limit", 20))
        except ValueError:
            n = 20
        return {"is_list": True, "is_detail": False, "per_page": max(1, n)}
    if p.startswith("/api/products/"):
        m = SKU.match(p.rsplit("/", 1)[1])
        return {"is_list": False, "is_detail": True, "per_page": 1, "product_id": int(m.group(1)) if m else None}
    if p.startswith("/api/v2/") and not p.startswith("/api/v2/auth/"):
        return {"is_list": False, "is_detail": False, "per_page": 1}
    return None


def caller_key(ctx):
    """Who is spending: the bearer subject when there is one, else the source address."""
    bearer = ctx.attrs.get("bearer")
    return f"sub:{bearer['sub']}" if bearer else f"ip:{ctx.ip}"


def score_rest(call, redis):
    """Return (points, reasons) for one REST call.

    ``call`` carries: key, is_list, is_detail, per_page, product_id (a detail of p017 has product_id 17).
    """
    # >>> SOLUTION round1 (cost budget, oversized pages, sequential enumeration)
    points, reasons = 0, []
    if call["is_list"] and call["per_page"] > MAX_PER_PAGE:
        points += BLOCK_POINTS
        reasons.append(f"oversized page: {call['per_page']} items asked (cap {MAX_PER_PAGE})")
    total = _spend(redis, call["key"], request_cost(call["is_list"], call["per_page"]))
    if total > COST_BUDGET:
        points += BLOCK_POINTS
        reasons.append(f"cost budget: {total} units in {int(WINDOW_S)}s (cap {COST_BUDGET})")
    if call["is_detail"] and call.get("product_id") is not None:
        ids = _record_id(redis, call["key"], call["product_id"])
        if _looks_sequential(ids):
            points += BLOCK_POINTS
            reasons.append(f"sequential enumeration: {len(ids)} ids walked in {int(WINDOW_S)}s")
    return min(points, 100), reasons
    # <<< SOLUTION round1


def _check(ctx):
    call = classify(ctx)
    if call is None:
        return None
    call["key"] = caller_key(ctx)
    points, reasons = score_rest(call, ctx.redis)
    if not points:
        return None
    signals = tuple(Signal("rate_cost", r.split(":")[0].replace(" ", "_"), points if i == 0 else 0, r) for i, r in enumerate(reasons))
    ctx.note(rest_cost_reasons=reasons)
    if any(r.startswith("cost budget") for r in reasons):
        return Verdict("rate_limit", signals=signals, retry_after=int(WINDOW_S))
    return signals


CHECK = Check("rate_cost", _check, phases=("request",))
