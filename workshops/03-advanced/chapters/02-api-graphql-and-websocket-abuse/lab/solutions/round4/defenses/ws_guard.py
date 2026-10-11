"""L4 — WebSocket connection guard (Round 4).

HTTP rate limiting counts requests or connection openings. A WebSocket is opened
once and then carries an unbounded number of messages over a single long-lived
connection, so an HTTP limiter never sees the flood. Worse, a browser will open a
WebSocket to your origin from *any* page the victim visits unless you check the
Origin header — cross-site WebSocket hijacking (CSWSH) — because the same-origin
policy does not apply to the WS handshake and there is no CORS preflight.

Three controls applied at and after the handshake:

  * **Origin allowlist** — reject the handshake if the Origin header is not one of
    ours. This is the CSWSH defence; the browser always sends Origin on a WS
    handshake, and a non-browser client that forges it is no worse off than any
    other unauthenticated caller.
  * **Auth on connect** — require a valid bearer token at connect time and bind
    the connection to that subject. An anonymous socket can read public feed
    frames but cannot send state-changing messages (a bid).
  * **Per-connection token bucket** — meter messages per connection. Legitimate
    clients send a trickle (a bid, a heartbeat); a flood drains the bucket and the
    connection is closed.

For multiple WS servers behind a load balancer, move the bucket into Redis keyed
on the subject so a bot cannot spread its flood across servers; the in-process
bucket here is enough for one server and keeps the lab dependency-free.

False positives: a shared NAT does not matter here because the bucket is per
connection, not per IP. The real risk is setting the bucket too low for a chatty
but legitimate client (a live dashboard), so size it from the real client's peak.
"""

from __future__ import annotations

import os
import time

PORT = int(os.environ.get("PORT", "5000"))
ALLOWED_ORIGINS = {
    f"http://127.0.0.1:{PORT}",
    f"http://localhost:{PORT}",
}
BUCKET_CAPACITY = 20      # burst of messages allowed
BUCKET_REFILL_PER_S = 5.0  # sustained messages per second


class ConnBucket:
    """A token bucket, one per WebSocket connection."""

    def __init__(self, capacity: int = BUCKET_CAPACITY, refill: float = BUCKET_REFILL_PER_S):
        self.capacity = capacity
        self.refill = refill
        self.tokens = float(capacity)
        self.ts = time.monotonic()
        self.violations = 0

    def allow(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.refill)
        self.ts = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        self.violations += 1
        return False


def check_origin(origin: str | None) -> bool:
    # >>> SOLUTION round4 (origin allowlist)
    return bool(origin) and origin in ALLOWED_ORIGINS
    # <<< SOLUTION round4


def authorize(origin: str | None, subject: str | None, action_needs_auth: bool) -> tuple[bool, str]:
    """Return (ok, reason) for the handshake / first state-changing message."""
    # >>> SOLUTION round4 (auth on connect)
    if not check_origin(origin):
        return False, f"origin not allowed: {origin!r}"
    if action_needs_auth and not subject:
        return False, "unauthenticated connection cannot send state-changing messages"
    return True, ""
    # <<< SOLUTION round4


def message_allowed(bucket: ConnBucket) -> tuple[bool, str]:
    # >>> SOLUTION round4 (per-connection rate)
    if bucket.allow():
        return True, ""
    return False, "per-connection message rate exceeded"
    # <<< SOLUTION round4
