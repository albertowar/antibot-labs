"""
Round 4 (level 4) - WebSocket connection guard.

HTTP rate limiting counts requests or connection openings. A WebSocket is opened once and then carries an
unbounded number of messages over a single long-lived connection, so an HTTP limiter never sees the flood.
Worse, a browser will open a WebSocket to your origin from *any* page the victim visits unless you check the
Origin header - cross-site WebSocket hijacking (CSWSH) - because the same-origin policy does not apply to the WS
handshake and there is no CORS preflight.

How the gate sees a WebSocket (see demo_site/ext/ws_feed.py): the handshake is a plain GET in the ``request``
phase, and after the upgrade the route runs the ladder once per frame in the ``ws:message`` phase, with the
per-connection state in ``ctx.attrs["ws"]``. One check, two phases: ``_check`` below dispatches on
``ctx.phase``. Three controls, each a function you write:

  * **Origin allowlist** (``check_origin``) - reject the handshake if the Origin header is not one of ours. This
    is the CSWSH defence; the browser always sends Origin on a WS handshake, and a non-browser client that
    forges it is no worse off than any other unauthenticated caller.
  * **Auth for state-changing messages** (``authorize``) - an anonymous socket can read public feed frames but
    cannot send a bid. The connection is bound to the bearer subject given at connect time (``?token=``).
  * **Per-connection token bucket** (``message_allowed``) - meter messages per connection. Legitimate clients
    send a trickle (a subscribe, a bid, a heartbeat); a flood drains the bucket, and the third refusal makes the
    server hang up.

For multiple WS servers behind a load balancer, move the bucket into Redis keyed on the subject so a bot cannot
spread its flood across servers; the in-process bucket here is enough for one server and keeps the lab simple.
(Not ``ctx.bucket``: its Lua script serializes under threads on the in-process Redis, and a 200-frame flood
would bury the gate-cost numbers.)

False positives: a shared NAT does not matter here because the bucket is per connection, not per address. The
real risk is setting the bucket too low for a chatty but legitimate client (a live dashboard), so size it from
the real client's peak. A privacy extension that strips Origin, or a native client that never sent one, is
refused by the strict check below: decide whether you serve them.
"""

import time
from urllib.parse import urlsplit

from .pipeline import Check, Signal, Verdict

BUCKET_CAPACITY = 10       # burst of messages allowed
BUCKET_REFILL_PER_S = 5.0  # sustained messages per second
MAX_VIOLATIONS = 3         # refused messages before the server hangs up
BLOCK_POINTS = 80          # policy blocks at >= 75


class ConnBucket:
    """A token bucket, one per WebSocket connection."""

    def __init__(self, capacity=BUCKET_CAPACITY, refill=BUCKET_REFILL_PER_S):
        self.capacity = capacity
        self.refill = refill
        self.tokens = float(capacity)
        self.ts = time.monotonic()
        self.violations = 0

    def allow(self):
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.refill)
        self.ts = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        self.violations += 1
        return False


def same_origin(origin, host):
    """True when the Origin header names this very host (scheme aside): what a browser sends from our own pages."""
    return bool(origin) and urlsplit(origin).netloc == host


def check_origin(origin, host):
    # TODO (Round 4): return True only when the Origin is ours (same_origin(origin, host)).
    return True


def authorize(origin, host, subject, needs_auth):
    """Return (ok, reason) for the handshake (needs_auth=False) or a state-changing message (needs_auth=True)."""
    # TODO (Round 4): reject a disallowed Origin (CSWSH), and reject an unauthenticated connection that tries a
    # state-changing action (a bid). Write the reason as "<short name>: <detail>".
    return True, ""


def message_allowed(bucket):
    # TODO (Round 4): meter messages with the per-connection token bucket (bucket.allow()).
    return True, ""


def _check(ctx):
    if ctx.phase == "request":
        if not ctx.path.startswith("/ws/"):
            return None
        ok, reason = authorize(ctx.header("Origin"), ctx.host, None, False)
        if ok:
            return None
        return Verdict("block", signals=(Signal("ws_guard", reason.split(":")[0].replace(" ", "_"), BLOCK_POINTS, reason),))
    # ws:message - one frame of an open connection
    state = ctx.attrs["ws"]
    bucket = state.setdefault("bucket", ConnBucket())
    ok, reason = message_allowed(bucket)
    if not ok:
        state["reason"] = reason
        state["close"] = bucket.violations >= MAX_VIOLATIONS
        return Verdict("rate_limit", signals=(Signal("ws_guard", "message_rate", BLOCK_POINTS, reason),), retry_after=1)
    if (state.get("msg") or {}).get("action") == "bid":
        ok, reason = authorize(state["origin"], ctx.host, state["subject"], True)
        if not ok:
            state["reason"] = reason
            return Verdict("block", signals=(Signal("ws_guard", reason.split(":")[0].replace(" ", "_"), BLOCK_POINTS, reason),))
    return None


CHECK = Check("ws_guard", _check, phases=("request", "ws:*"))
