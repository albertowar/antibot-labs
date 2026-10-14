"""
login_throttle (Round 1): per-IP velocity and per-account lockout. The first, cheapest layer.

Two independent counters:

  * per-IP sliding window: catches one source hammering the endpoint. Checked BEFORE the
    password is verified, so a flood costs a Redis call, not a PBKDF2 hash.
  * per-account consecutive failures: catches someone grinding one account even if they rotate
    IPs, and resets to zero on the first success.

NIST SP 800-63B-4 (2025) caps online guessing at no more than 100 consecutive failed attempts
per authenticator. That is an upper bound; agencies may set a lower one. We lock at 10: low
enough to stop targeted guessing, high enough that a fat-fingered human rarely reaches it.

What it misses: a stuffer that tries each account ONCE from a different IP trips neither
counter. That gap is what Round 2 exists to close.

Who it hurts: everyone behind a shared address. Carrier-grade NAT puts hundreds of phones on one
IP; a 30-per-minute limit refuses the 31st person through no fault of their own. Keep the limit
high, and never let it be the only layer. Per-account lockout has a second cost: an attacker can
lock a victim out on purpose (a denial of service on one account). The lock here expires after
15 minutes instead of waiting for a human at the help desk.

The check runs in two phases of the login: `action:login` (before the password is checked) and
`action:login_result` (after, when the store says whether it was right).

Helper (finished): ratelimit.hit(redis, key, window_s) -> events in the sliding window, this one included
                   ratelimit.incr_window(redis, key, window_s) -> a counter that dies with its window
Reference: solutions/round1/defenses/login_throttle.py (or `checkpoint.py --round 1 --catch-up`)
"""

import time

from . import ratelimit
from .pipeline import Check, Signal, Verdict

IP_LIMIT = 30           # attempts ...
IP_WINDOW_S = 60        # ... per minute from one IP
LOCK_AFTER = 10         # consecutive failures on one account ...
LOCK_WINDOW_S = 900     # ... lock it for 15 minutes
NIST_HARD_CAP = 100     # absolute ceiling from SP 800-63B-4


def _pre_auth(ctx):
    rds, email = ctx.redis, ctx.notes.get("email", "")
    # TODO (Round 1): two refusals, cheapest first. Return Verdict("rate_limit", retry_after=...,
    #   signals=(Signal("rate_limit", "<name>", 0, "<why>"),)) for each, or None to let the login run.
    #   1. The account is locked: a key `lab:ato:lock:<email>` exists in Redis.
    #   2. This IP made more than IP_LIMIT logins in IP_WINDOW_S: ratelimit.hit(rds, f"lab:ato:ip:{ctx.ip}", ...).
    return None


def _record(ctx):
    login = ctx.attrs.get("login")      # {"ok": bool, "email": str, "known": bool, "password": str}
    if not login:
        return None
    # TODO (Round 1): keep the per-account consecutive-failure counter `lab:ato:fail:<email>`.
    #   On success: delete it. On failure: ratelimit.incr_window(rds, key, LOCK_WINDOW_S) and, at
    #   LOCK_AFTER, set the lock flag `lab:ato:lock:<email>` for LOCK_WINDOW_S seconds
    #   (rds.setex). Return None either way: the attempt already got its answer.
    return None


def _check(ctx):
    return _pre_auth(ctx) if ctx.phase == "action:login" else _record(ctx)


CHECK = Check("login_throttle", _check, phases=("action:login", "action:login_result"))
