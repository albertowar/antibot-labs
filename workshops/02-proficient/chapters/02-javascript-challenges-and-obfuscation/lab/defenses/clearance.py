"""
Chapter 2 — Round 5 defense: clearance budgets (Section 2.5, Round 5)

Round 4's attacker pays for a real browser once, then hands the clearance
cookie (and the session cookie, and the UA) to a fast HTTP client. The
browser costs seconds; the next 10,000 requests cost milliseconds each.
This is clearance harvesting, and it's how most "JS challenge bypass" tooling
works in practice.

You can't stop the handoff: every byte the browser holds can be copied.
What you can do is cap what one solve buys:

  - a request budget per clearance (here 30), counted in Redis per clearance
    (the session plus the moment it was granted), and
  - a short lifetime (here 10 minutes).

Over budget, the request gets a fresh challenge. A real browser solves it
without the user noticing (the challenge page reloads itself). The harvester
has to go back to the browser.

This doesn't block anyone. It turns "one browser solve per scrape" into
"one browser solve per 30 pages", so the attacker's cost grows with volume
and a human's doesn't.

Trade-offs:
  - Legitimate power users (and your own SPA, which may fire 10 API calls per
    view) hit the budget too. Size it from real traffic: p99 requests per
    session-minute, not a guess. Count page views, not every XHR, if you can.
  - Every re-challenge is a round trip plus script execution. That's
    noticeable on slow devices, and a nightmare for screen-reader users if
    the interstitial steals focus.
  - Redis now sits on the request path (one INCR per request). Budget for
    its latency and decide what happens when it's down: fail open or closed?
"""

import os

BUDGET = int(os.environ.get("CLEARANCE_BUDGET", "30"))
TTL_S = 600


def consume(redis, clearance_id):
    """Count one request against this clearance. Returns (allowed, used)."""
    key = f"lab:jsc:budget:{clearance_id}"
    used = redis.incr(key)
    if used == 1:
        redis.expire(key, TTL_S)
    # TODO (Round 5, optional): what budget would a real user on your busiest page need?
    return used <= BUDGET, used


if __name__ == "__main__":
    import fakeredis
    redis = fakeredis.FakeRedis()
    results = [consume(redis, "demo")[0] for _ in range(BUDGET + 3)]
    print(f"{results.count(True)} requests allowed, then {results.count(False)} re-challenged")
