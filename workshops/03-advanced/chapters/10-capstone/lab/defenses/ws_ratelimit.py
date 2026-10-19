"""
Level 5: a per-connection WebSocket message rate limit (W3 Ch2).

A WebSocket is one long-lived connection, so per-request HTTP rate limits never see it: after the upgrade, a client
can push thousands of messages down the same socket. The cheap, robust control is a token bucket *per connection*,
independent of the address and of how many connections the client opens.

    capacity      burst the client may send before refill matters   (policy.WS_BURST)
    refill_per_s  sustained messages per second allowed long-term   (policy.WS_REFILL_PER_S)

allow() is a pure function of time and state, unit-tested in __main__, so the feed (demo_site/ext/api9.py) stays a
thin wrapper around it. It is not `ctx.bucket`: that is a Lua script on the shared Redis, which serializes under
threads on the in-process store and would bury the gate-cost numbers (TODO.md section 1.2, the W3 Ch4 gap).
"""

import time

from . import policy


class TokenBucket:
    def __init__(self, capacity=None, refill_per_s=None, now=None):
        self.capacity = float(policy.WS_BURST if capacity is None else capacity)
        self.refill = float(policy.WS_REFILL_PER_S if refill_per_s is None else refill_per_s)
        self._now = now or time.monotonic
        self.tokens = self.capacity
        self.ts = self._now()

    def allow(self, cost=1.0):
        now = self._now()
        self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.refill)
        self.ts = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


if __name__ == "__main__":
    clock = {"t": 0.0}
    b = TokenBucket(capacity=20, refill_per_s=5.0, now=lambda: clock["t"])
    allowed = sum(b.allow() for _ in range(100))      # an instant burst of 100
    assert allowed == 20, allowed                      # only the bucket's capacity gets through
    clock["t"] = 2.0                                   # 2 s later: +10 tokens refilled
    allowed2 = sum(b.allow() for _ in range(100))
    assert allowed2 == 10, allowed2
    print(f"ws_ratelimit self-test OK: burst {allowed}/100, then {allowed2}/100 after 2 s of refill")
