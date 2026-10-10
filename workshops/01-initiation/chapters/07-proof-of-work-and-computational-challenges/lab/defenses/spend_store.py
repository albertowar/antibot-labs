"""
Chapter 7 — Server-side state for PoW (Rounds 3 and 4, Section 7.3)

A stateless verifier (Rounds 1-2) cannot tell a fresh solution from a
replayed one. From Round 3 on, the server remembers three things:

  spend_once(key)   a challenge nonce can be redeemed once   (SET NX EX)
  incr(key)         how many requests a pass has paid for    (INCR + EXPIRE)
  hit(key, window)  requests per client in a sliding window  (sorted set)

Two backends with the same interface:

  STORE=redis  (default) Redis from ../docker-compose.yml, REDIS_URL to override.
               Shared by every app worker, survives restarts, and costs one
               network round trip per operation.
  STORE=memory a dict in this process. Fine for the lab, wrong for production:
               with 4 gunicorn workers a nonce can be spent 4 times.

Trade-off: this is the price of replay protection. The server now pays
one or two store operations per protected request, and the store becomes
a dependency. If Redis is down, do you fail open (let everyone through)
or fail closed (block everyone)? Write that decision down before the
incident, not during it.

Run the self-test:
    STORE=memory python defenses/spend_store.py
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque


class MemoryStore:
    """In-process store. Single-process only: see the module docstring."""

    def __init__(self):
        self._lock = threading.Lock()
        self._expiry: dict[str, float] = {}
        self._counts: dict[str, int] = {}
        self._hits: dict[str, deque] = {}
        self.ops = 0

    def _alive(self, key, now):
        exp = self._expiry.get(key)
        if exp is not None and exp <= now:
            self._expiry.pop(key, None)
            self._counts.pop(key, None)
            return False
        return key in self._expiry

    def spend_once(self, key: str, ttl: int) -> bool:
        """Mark key as used. True the first time, False on every replay."""
        with self._lock:
            self.ops += 1
            now = time.time()
            if self._alive(key, now):
                return False
            self._expiry[key] = now + ttl
            return True

    def incr(self, key: str, ttl: int) -> int:
        """Increment a counter that expires `ttl` seconds after its first use."""
        with self._lock:
            self.ops += 1
            now = time.time()
            if not self._alive(key, now):
                self._expiry[key] = now + ttl
                self._counts[key] = 0
            self._counts[key] += 1
            return self._counts[key]

    def hit(self, key: str, window: int, record: bool = True) -> int:
        """Record one request now; return the requests seen in the last `window` s."""
        with self._lock:
            self.ops += 1
            now = time.time()
            q = self._hits.setdefault(key, deque())
            while q and q[0] <= now - window:
                q.popleft()
            if record:
                q.append(now)
            return len(q)

    def reset(self):
        with self._lock:
            self._expiry.clear()
            self._counts.clear()
            self._hits.clear()


class RedisStore:
    """Redis-backed store; every app process shares the same state."""

    def __init__(self, url: str):
        import redis  # imported here so STORE=memory works without the package
        self.r = redis.Redis.from_url(url)
        self.r.ping()  # fail at startup, not on the first protected request
        self.ops = 0

    def spend_once(self, key, ttl):
        self.ops += 1
        return bool(self.r.set(key, 1, nx=True, ex=ttl))

    def incr(self, key, ttl):
        self.ops += 1
        pipe = self.r.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl, nx=True)  # set the TTL only on first use
        return pipe.execute()[0]

    def hit(self, key, window, record=True):
        self.ops += 1
        now = time.time()
        pipe = self.r.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        if record:
            pipe.zadd(key, {f"{now:.6f}:{os.urandom(4).hex()}": now})
            pipe.expire(key, window)
        pipe.zcard(key)
        return pipe.execute()[-1]

    def reset(self):
        for key in self.r.scan_iter("pow:*"):
            self.r.delete(key)


def get_store():
    """Build the store selected by STORE (redis|memory)."""
    kind = os.environ.get("STORE", "redis").lower()
    if kind == "memory":
        return MemoryStore()
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    try:
        return RedisStore(url)
    except Exception as exc:  # redis missing or not running
        raise SystemExit(
            f"❌ Redis not reachable at {url} ({exc.__class__.__name__}).\n"
            "   Start it with `docker compose up -d --wait`, or run without Docker:\n"
            "   STORE=memory DEFENSE_LEVEL=<n> python app.py") from exc


if __name__ == "__main__":
    store = get_store()
    store.reset()
    assert store.spend_once("pow:test:nonce", 5) is True
    assert store.spend_once("pow:test:nonce", 5) is False, "replay must fail"
    assert [store.incr("pow:test:pass", 5) for _ in range(3)] == [1, 2, 3]
    assert [store.hit("pow:test:rate", 60) for _ in range(3)] == [1, 2, 3]
    store.reset()
    print(f"✅ {type(store).__name__} self-test passed")
