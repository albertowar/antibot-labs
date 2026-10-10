"""Round 3 attack — infostealer log replay.

Credential stuffing tests *leaked* passwords, so breach screening (L3) kills it.
This attack sidesteps that entirely: it uses credentials an infostealer lifted
straight from the victim's browser. They are correct, current, and have never
appeared in any breach corpus — so the breach screen sees nothing. The malware
also grabbed the victim's device cookie and user-agent, which the attacker
replays. The one thing it cannot fake is the victim's network.

Against L3 this walks straight in. Against L4's device/context check it is stopped,
because the login arrives on an ASN the account has never used.
"""

from __future__ import annotations

import asyncio

import httpx

from _common import BASE_URL, edge_headers, is_success, load_json, require_local_target

ATTACKER_IP = "198.51.100.50"   # datacenter egress — not the victims' home network
ACTOR = "bot:round3"


async def run() -> dict:
    require_local_target(BASE_URL)
    logs = load_json("stealer_logs.json")
    hits: list[str] = []

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        for v in logs:
            try:
                r = await client.post(
                    "/login",
                    json={"email": v["email"], "password": v["password"]},
                    headers=edge_headers(ACTOR, ATTACKER_IP, device=v["did"],
                                         client_sig=v["client_sig"], user_agent=v["user_agent"]),
                )
                if is_success(r):
                    hits.append(v["email"])
            except httpx.RequestError:
                pass

    return {"attack": ACTOR, "attempts": len(logs), "accounts_taken_over": len(hits),
            "hits": sorted(hits)}


def main():
    result = asyncio.run(run())
    print(f"[{result['attack']}] {result['attempts']} stolen credentials -> "
          f"{result['accounts_taken_over']} accounts taken over")


if __name__ == "__main__":
    main()
