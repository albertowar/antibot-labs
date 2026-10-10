"""L1 reference: per-IP velocity + per-account lockout.

The first and cheapest layer. Two independent counters:

  * per-IP sliding window — catches a single source hammering the endpoint.
  * per-account consecutive failures — catches someone grinding one account,
    *even if they rotate IPs*, and resets to zero on the first success.

NIST SP 800-63B-4 (2025) caps online guessing at no more than 100 consecutive
failed attempts per authenticator; that is an upper bound, and agencies may set a
lower one. We lock at 10 — low enough to stop targeted guessing, high enough that
a fat-fingered human rarely reaches it. The deliberate gap this layer leaves: a
stuffer that tries each account *once* from a different IP trips neither counter.
That gap is what L2 exists to close.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from defenses import ratelimit  # noqa: E402

IP_LIMIT = 30          # attempts ...
IP_WINDOW_S = 60       # ... per minute from one IP
LOCK_AFTER = 10        # consecutive failures on one account ...
LOCK_WINDOW_S = 900    # ... locks it for 15 minutes
NIST_HARD_CAP = 100    # absolute ceiling from SP 800-63B-4 §5.1.1.2


def pre_auth(ctx) -> str | None:
    rds, ip, email = ctx["rds"], ctx["client_ip"], ctx["email"]
    if rds.get(f"lock:{email}"):
        return "account temporarily locked (too many failed attempts)"
    if ratelimit.hit(rds, f"ip:{ip}", IP_WINDOW_S, ctx["now"]) > IP_LIMIT:
        return f"per-IP rate limit exceeded ({IP_LIMIT}/{IP_WINDOW_S}s)"
    return None


def record(ctx, ok: bool) -> None:
    rds, email = ctx["rds"], ctx["email"]
    key = f"fail:{email}"
    if ok:
        rds.delete(key)
        return
    fails = ratelimit.incr_window(rds, key, LOCK_WINDOW_S, ctx["now"])
    if fails >= LOCK_AFTER:
        rds.setex(f"lock:{email}", LOCK_WINDOW_S, "1")
