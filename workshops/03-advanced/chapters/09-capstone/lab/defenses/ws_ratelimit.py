"""
Capstone L5 — per-connection WebSocket message rate limit (W3 Ch2)

A WebSocket is one long-lived connection, so per-request HTTP rate limits never
see it: after the upgrade, a client can push thousands of messages down the
same socket. The cheap, robust control is a token bucket *per connection* —
independent of IP, independent of how many connections the client opens.

    capacity      burst the client may send before refill matters
    refill_per_s  sustained messages/second allowed long-term

allow() is a pure function of time and state, unit-tested in __main__, so the
server (demo_site/wsserver.py) stays a thin wrapper around it.
"""

import time


class TokenBucket:
    def __init__(self, capacity=20, refill_per_s=5.0, now=None):
        self.capacity = float(capacity)
        self.refill = float(refill_per_s)
        self.tokens = float(capacity)
        self.ts = (now or time.monotonic)()
        self._now = now or time.monotonic

    def allow(self, cost=1.0):
        now = self._now()
        self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.refill)
        self.ts = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


if __name__ == '__main__':
    clock = {"t": 0.0}
    b = TokenBucket(capacity=20, refill_per_s=5.0, now=lambda: clock["t"])
    allowed = sum(b.allow() for _ in range(100))      # instant burst of 100
    assert allowed == 20, allowed                      # only the bucket's capacity gets through
    clock["t"] = 2.0                                   # 2 s later: +10 tokens refilled
    allowed2 = sum(b.allow() for _ in range(100))
    assert allowed2 == 10, allowed2
    print(f"ws_ratelimit self-test OK: burst {allowed}/100 then {allowed2}/100 after 2s refill")
