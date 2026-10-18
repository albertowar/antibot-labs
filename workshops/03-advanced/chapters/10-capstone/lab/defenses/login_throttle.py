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
    if rds.get(f"lab:ato:lock:{email}"):
        return Verdict("rate_limit", retry_after=60,
                       signals=(Signal("rate_limit", "account_locked", 0, "too many failed attempts on this account"),))
    if ratelimit.hit(rds, f"lab:ato:ip:{ctx.ip}", IP_WINDOW_S, time.time()) > IP_LIMIT:
        return Verdict("rate_limit", retry_after=IP_WINDOW_S,
                       signals=(Signal("rate_limit", "ip_velocity", 0, f"over {IP_LIMIT} logins in {IP_WINDOW_S} s from {ctx.ip}"),))
    return None


def _record(ctx):
    login = ctx.attrs.get("login")
    if not login:
        return None
    rds, key = ctx.redis, f"lab:ato:fail:{login['email']}"
    if login["ok"]:
        rds.delete(key)
        return None
    if ratelimit.incr_window(rds, key, LOCK_WINDOW_S) >= LOCK_AFTER:
        rds.setex(f"lab:ato:lock:{login['email']}", LOCK_WINDOW_S, "1")
    return None


def _check(ctx):
    return _pre_auth(ctx) if ctx.phase == "action:login" else _record(ctx)


CHECK = Check("login_throttle", _check, phases=("action:login", "action:login_result"))
