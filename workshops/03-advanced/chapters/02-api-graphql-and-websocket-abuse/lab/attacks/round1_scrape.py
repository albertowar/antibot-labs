"""Round 1 attack — REST catalogue scraping: pagination + id enumeration.

Two classic REST-scraping moves against the versioned API:

  * **oversized pagination** — ask for the biggest page the endpoint will give
    (``per_page=100``) and walk every page, pulling the catalogue in O(pages).
  * **id enumeration** — hit ``/api/v2/products/<id>`` for id = 1, 2, 3, …, which
    also surfaces the internal ``hidden`` SKUs that are never linked from the UI.

At DEFENSE_LEVEL=0 both walk the whole store in seconds. At DEFENSE_LEVEL=1 the
cost-aware limiter blocks the oversized walk on budget and the sequential
enumeration on the walk pattern. The attack is deliberately just strong enough to
drain the catalogue and trip the detector — it is a teaching tool against your own
local store, not a general scraper.
"""

from __future__ import annotations

import time

import httpx

from _common import BASE_URL, headers, require_local_target

ACTOR = "bot-r1"


def run(base: str = BASE_URL) -> dict:
    require_local_target(base)
    h = headers(ACTOR)
    seen, blocked, reqs = {}, 0, 0
    t0 = time.perf_counter()
    with httpx.Client(base_url=base, headers=h, timeout=10) as c:
        # Oversized pagination walk.
        page = 1
        while page <= 10:
            r = c.get("/api/v2/products", params={"page": page, "per_page": 100})
            reqs += 1
            if r.status_code != 200:
                blocked += 1
                break
            data = r.json()
            for it in data["items"]:
                seen[it["id"]] = it
            if not data["has_more"]:
                break
            page += 1
        # Id enumeration (also finds hidden internal SKUs).
        for pid in range(1, 501):
            r = c.get(f"/api/v2/products/{pid}")
            reqs += 1
            if r.status_code == 200:
                seen[pid] = r.json()
            elif r.status_code == 403:
                blocked += 1
    elapsed = time.perf_counter() - t0
    hidden = sum(1 for v in seen.values() if str(v.get("sku", "")).startswith("internal-"))
    return {"actor": ACTOR, "products_scraped": len(seen), "hidden_found": hidden,
            "requests": reqs, "blocked": blocked, "elapsed_s": round(elapsed, 2)}


if __name__ == "__main__":
    s = run()
    print(f"[round1] scraped {s['products_scraped']} products "
          f"({s['hidden_found']} hidden internal SKUs) in {s['requests']} requests, "
          f"{s['blocked']} blocked, {s['elapsed_s']}s")
