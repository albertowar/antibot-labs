"""L1: per-IP velocity + per-account lockout.  <-- you implement this in Round 1.

Fill in the TODOs so that:
  * more than IP_LIMIT attempts from one IP inside IP_WINDOW_S is throttled, and
  * LOCK_AFTER consecutive failures on one account locks it for LOCK_WINDOW_S,
    with a success resetting the counter.

Helpers are ready for you in ``defenses/ratelimit.py``:
    ratelimit.hit(rds, key, window_s, now)         -> count in the sliding window
    ratelimit.incr_window(rds, key, window_s, now)  -> fixed-window counter value

Reference solution: defenses/solutions/login_throttle.py
Run ``python tools/checkpoint.py --round 1 --catch-up`` to use the reference.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from defenses import ratelimit  # noqa: E402

IP_LIMIT = 30
IP_WINDOW_S = 60
LOCK_AFTER = 10
LOCK_WINDOW_S = 900
NIST_HARD_CAP = 100  # SP 800-63B-4 upper bound on consecutive failures


def pre_auth(ctx) -> str | None:
    # TODO (Round 1): return a reason string to block, or None to allow.
    #   1. If a lock flag exists for ctx["email"], return a lock reason.
    #   2. Record this IP hit and, if it exceeds IP_LIMIT in IP_WINDOW_S,
    #      return a rate-limit reason.
    return None


def record(ctx, ok: bool) -> None:
    # TODO (Round 1): maintain the per-account consecutive-failure counter.
    #   On success: clear it. On failure: increment it and, at LOCK_AFTER,
    #   set a lock flag on ctx["email"] for LOCK_WINDOW_S seconds.
    return None
