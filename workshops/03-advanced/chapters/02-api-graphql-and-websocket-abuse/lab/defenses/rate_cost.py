"""L1 — cost-aware rate limiting for the REST API (Round 1).

Counting requests is the wrong unit for an API. One ``GET /api/v2/products
?per_page=100`` costs a backend far more than one ``GET /api/v2/products/5``, yet
a request-counting limiter scores them the same. A bot that walks pagination with
a large page size, or enumerates ``/products/<id>`` in order, drains the whole
catalogue while staying under a naive per-minute cap.

Two complementary signals, both keyed on the caller (bearer subject if present,
else the egress IP), over a short sliding window:

  * a **cost budget**: each request spends cost proportional to how much data it
    asks for, and a caller that overspends the budget is blocked. This catches
    the fast, large-page walker.
  * an **enumeration penalty**: a caller that pulls many *sequential* product ids
    in the window is walking the catalogue by id, which no human browsing session
    does. This catches the slow walker that stays under the cost budget.

False positives to keep in mind (see the chapter's "where this stops" section):
shared egress IPs (CGNAT, a corporate NAT, a mobile carrier) concentrate many
real users onto one key, so key on an authenticated subject wherever you can and
keep the IP budget generous. API gateways and server-side rendering fan out to
your API legitimately; allowlist them rather than tuning the budget down.
"""

from __future__ import annotations

import math
import time

WINDOW_S = 10.0          # sliding window
COST_BUDGET = 40         # cost units per key per window before we block
MAX_PER_PAGE = 50        # a page larger than this is clamped and penalised
ENUM_THRESHOLD = 30      # distinct ids in the window before we look at ordering
ENUM_SEQ_FRACTION = 0.7  # fraction of consecutive ids that marks a walk

BLOCK_POINTS = 60        # engine blocks at >= 60


def request_cost(is_list: bool, per_page: int) -> int:
    """Cost a request spends against the budget: a list of N items costs ~N/10."""
    if is_list:
        return max(1, math.ceil(min(per_page, 500) / 10))
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
    # TODO (Round 1): implement cost-aware rate limiting.
    #   - spend request_cost(is_list, per_page) against a per-key budget
    #     (COST_BUDGET units per WINDOW_S) using _spend(store, key, weight);
    #   - add points for an oversized page (per_page > MAX_PER_PAGE);
    #   - add an enumeration penalty when _looks_sequential(_record_id(...)).
    # Until you do, the REST API is unprotected even at DEFENSE_LEVEL=1.
    # Catch up with: python tools/checkpoint.py --round 1 --catch-up
    return 0, []
