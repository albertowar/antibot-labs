"""
Chapter 2, Round 3 attack: be patient.

A token bucket closes the fixed window's boundary: there is no seam to ride, because the
bucket refills continuously instead of resetting. But a rate limit, any rate limit, only
limits RATE. Stay under it and you are invisible. The store even tells you the rate: every
429's Retry-After is how long until the next token. Wait exactly that long and every request
is a 200.

This is credential stuffing from a single address, paced by the store's own Retry-After. It
is slow, and slow is the price, but it never trips the limit.

    python attacks/round3_paced_login.py

Expected:   level 2 (fixed window): the boundary run beats it, this one also gets through.
            level 3 (token bucket + fixed window): the boundary run is now capped (partial),
            but this paced run still reaches the login logic for every attempt (full), in
            about 20-40 s. Rate limiting slows the patient attacker; it does not stop them.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import _common  # noqa: E402
from labclient import world_pool  # noqa: E402  (guard runs on import)
from demo_site.seed import weak_users  # noqa: E402


def run(n=30):
    pairs = (weak_users() * 3)[:n]        # reuse the stolen pairs to make a longer run
    ip = world_pool("cloud_vm")[0]
    return _common.stuff("r3_paced_login", pairs, lambda i: ip, respect_retry=True)


if __name__ == "__main__":
    _common.finish(run())
