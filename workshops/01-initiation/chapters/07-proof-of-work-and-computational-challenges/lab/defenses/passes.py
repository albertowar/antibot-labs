"""
Chapter 7 — The PoW pass: what a solved challenge buys (Rounds 1-3)

Nobody solves a puzzle per request. A solved challenge is exchanged for a
*pass*, a signed cookie that lets the client make protected requests for
a while. The pass is the product you are actually pricing:

    pass = "<pid>.<expires>.<bind>.<sig>"   sig = HMAC(secret, pid|expires|bind)

How generous the pass is decides what one solution is worth to a bot:

  L1-L2  PASS_TTL_LONG s, unlimited requests, not bound to the client.
         One solve buys the whole catalog (Round 2's attack).
  L3+    PASS_TTL s and PASS_BUDGET requests, bound to IP + User-Agent.
         Every PASS_BUDGET pages cost one more solve.

Trade-off: a stingy pass makes bots pay more, and real users pay more too.
A user reading 30 pages with PASS_BUDGET=20 solves twice. That is fine on
a laptop (about 0.1 s each) and noticeable on a cheap phone. Budget by
*action* (one pass per checkout or login attempt) where you can; budget by
request count only where the request itself is the thing being abused.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time

PASS_TTL_LONG = 600   # L1-L2
PASS_TTL = 120        # L3+
PASS_BUDGET = 20      # L3+: protected requests per solved challenge


def _sig(secret: bytes, pid: str, expires: int, bind: str) -> str:
    msg = f"pass|{pid}|{expires}|{bind}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()[:32]


def issue(secret: bytes, ttl: int, bind: str = "") -> tuple[str, str]:
    """Return (token, pass id)."""
    pid, expires = os.urandom(8).hex(), int(time.time()) + ttl
    return f"{pid}.{expires}.{bind}.{_sig(secret, pid, expires, bind)}", pid


def check(secret: bytes, token: str | None, bind: str = "") -> tuple[bool, str, str | None]:
    """Return (ok, reason, pass id). Budget is enforced by the caller (it needs the store)."""
    if not token:
        return False, "no PoW pass: solve /pow/challenge first", None
    try:
        pid, expires_s, p_bind, sig = token.split(".")
        expires = int(expires_s)
    except ValueError:
        return False, "malformed PoW pass", None
    if not hmac.compare_digest(_sig(secret, pid, expires, p_bind), sig):
        return False, "PoW pass signature invalid", None
    if time.time() > expires:
        return False, "PoW pass expired", None
    if p_bind and not hmac.compare_digest(p_bind, bind):
        return False, "PoW pass is bound to another client", None
    return True, "ok", pid
