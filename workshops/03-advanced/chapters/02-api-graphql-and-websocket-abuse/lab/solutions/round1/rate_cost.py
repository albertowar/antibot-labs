"""L1 — cost-aware rate limiting for the REST API (Round 1).

Counting requests is the wrong unit for an API. One ``GET /api/v2/products
?per_page=100`` costs a backend far more than one ``GET /api/v2/products/5``, yet
a request-counting limiter scores them the same. A bot that walks pagination with
a large page size, or enumerates ``/products/<id>`` in order, drains the whole
catalogue while staying under a naive per-minute cap.

Two complementary signals, both keyed on the caller (bearer subject if present,
else the egress IP), over a short sliding window:

  * a **cost budget**: each request spends cost proportional to how much data it
    asks for — one unit per item a list returns, one unit per detail — and a
    caller that overspends the budget is blocked. This catches the fast,
    large-page walker: a single ``per_page=100`` page spends 100 units.
  * an **enumeration penalty**: a caller that pulls many *sequential* product ids
    in the window is walking the catalogue by id, which no human browsing session
    does. This catches the walk pattern directly, including the slow walker.

False positives to keep in mind (see the chapter's "where this stops" section):
shared egress IPs (CGNAT, a corporate NAT, a mobile carrier) concentrate many
real users onto one key, so key on an authenticated subject wherever you can and
keep the IP budget generous. API gateways and server-side rendering fan out to
your API legitimately; allowlist them rather than tuning the budget down.
"""

from __future__ import annotations

import time

WINDOW_S = 10.0          # sliding window
COST_BUDGET = 150        # cost units (≈ items) per key per window before we block
MAX_PER_PAGE = 50        # a page larger than this is penalised (and clamped by the app)
ENUM_THRESHOLD = 30      # distinct sequential ids in the window before we block
ENUM_SEQ_FRACTION = 0.7  # fraction of consecutive ids that marks a walk

BLOCK_POINTS = 60        # engine blocks at >= 60


def request_cost(is_list: bool, per_page: int) -> int:
    """Cost a request spends: one unit per item a list returns, one per detail."""
    if is_list:
        return max(1, min(per_page, 500))
    return 1


def _spend(store, key: str, weight: int) -> int:
    """Add ``weight`` cost units to the window and return the window total."""
    nowf = time.time()
    rkey = f"cost:{key}"
    members = {f"{nowf:.6f}:{i}": nowf for i in range(max(1, weight))}
    pipe = store.pipeline()
    pipe.zremrangebyscore(rkey, 0, nowf - WINDOW_S)
    pipe.zadd(rkey, members)
    pipe.zcard(rkey)
    pipe.expire(rkey, int(WINDOW_S) + 1)
    _, _, total, _ = pipe.execute()
    return int(total)


def _record_id(store, key: str, product_id: int) -> list[int]:
    """Record a detail-page id hit and return the distinct ids seen in the window."""
    nowf = time.time()
    rkey = f"enum:{key}"
    pipe = store.pipeline()
    pipe.zremrangebyscore(rkey, 0, nowf - WINDOW_S)
    pipe.zadd(rkey, {str(product_id): nowf})
    pipe.zrange(rkey, 0, -1)
    pipe.expire(rkey, int(WINDOW_S) + 1)
    _, _, ids, _ = pipe.execute()
    return sorted(int(x) for x in ids)


def _looks_sequential(ids: list[int]) -> bool:
    """True when the distinct ids form a near-contiguous walk, like 1,2,3,4,…."""
    if len(ids) < ENUM_THRESHOLD:
        return False
    consecutive = sum(1 for a, b in zip(ids, ids[1:]) if b - a == 1)
    return consecutive / (len(ids) - 1) >= ENUM_SEQ_FRACTION


def score_rest(ctx: dict, store, count: bool = True) -> tuple[int, list[str]]:
    """Return (points, reasons) for one REST request.

    ``ctx`` carries: key, is_list, per_page, is_detail, product_id.
    """
    points = 0
    reasons: list[str] = []
    key = ctx["key"]
    per_page = int(ctx.get("per_page", 20) or 20)

    if ctx.get("is_list") and per_page > MAX_PER_PAGE:
        points += 15
        reasons.append(f"oversized page per_page={per_page} (cap {MAX_PER_PAGE})")

    if count:
        weight = request_cost(bool(ctx.get("is_list")), per_page)
        total = _spend(store, key, weight)
        if total > COST_BUDGET:
            points += BLOCK_POINTS
            reasons.append(f"cost budget exceeded: {total} units/{int(WINDOW_S)}s (cap {COST_BUDGET})")

        if ctx.get("is_detail") and ctx.get("product_id") is not None:
            ids = _record_id(store, key, int(ctx["product_id"]))
            if _looks_sequential(ids):
                points += BLOCK_POINTS
                reasons.append(f"sequential id enumeration: {len(ids)} ids walked in {int(WINDOW_S)}s")

    return min(points, 100), reasons
