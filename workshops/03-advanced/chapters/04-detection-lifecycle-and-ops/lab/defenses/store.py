"""
Shared counter store, inherited from W2 Ch8 (Redis, or memory:// without Docker)

Several layers keep state that has to be the same on every app server:
per-IP velocity, telemetry replay, fingerprint reuse and the campaign
counters. In production that state lives in Redis (or Valkey), never in one
process. Two app servers that each keep their own counters see half the
attack each.

    REDIS_URL=redis://localhost:6379/0   default, from ../docker-compose.yml
    REDIS_URL=memory://                  in-process fallback for laptops without Docker

Trade-offs:
- Every counter is a network round trip on the request path. The pipeline
  makes about ten of them per login, which is most of the "defender cost"
  that the checkpoint reports. Batch with pipelines or move the
  non-blocking counters off the request path once you have more traffic.
- Fixed windows (INCR + EXPIRE) are cheap but reset all at once. An attacker
  who learns the window can pace around it (Round 4).
- If Redis is down, decide per layer whether to fail open or closed
  (Section 8.4). This lab fails loudly so you notice.
"""

import fnmatch
import os
import threading
import time

PREFIX = "w3ch4:"
WINDOW_S = 600  # every counter in this lab uses a 10-minute window


class MemoryStore:
    """Just enough of the Redis API for the lab, with expiry. Thread-safe."""

    def __init__(self):
        self._data, self._expiry = {}, {}
        self._lock = threading.Lock()

    def _live(self, key):
        if key in self._expiry and self._expiry[key] < time.time():
            self._data.pop(key, None)
            self._expiry.pop(key, None)
        return key in self._data

    def get(self, key):
        with self._lock:
            return self._data.get(key) if self._live(key) else None

    def set(self, key, value, ex=None):
        with self._lock:
            self._data[key] = str(value)
            if ex:
                self._expiry[key] = time.time() + ex

    def incr(self, key):
        with self._lock:
            value = int(self._data[key]) + 1 if self._live(key) else 1
            self._data[key] = str(value)
            return value

    def expire(self, key, seconds):
        with self._lock:
            if self._live(key):
                self._expiry[key] = time.time() + seconds

    def sadd(self, key, member):
        with self._lock:
            if not self._live(key):
                self._data[key] = set()
            self._data[key].add(member)

    def scard(self, key):
        with self._lock:
            return len(self._data[key]) if self._live(key) else 0

    def hincrby(self, key, field, amount=1):
        with self._lock:
            if not self._live(key):
                self._data[key] = {}
            self._data[key][field] = self._data[key].get(field, 0) + amount
            return self._data[key][field]

    def hgetall(self, key):
        with self._lock:
            return {k: str(v) for k, v in self._data[key].items()} if self._live(key) else {}

    def delete(self, *keys):
        with self._lock:
            for key in keys:
                self._data.pop(key, None)
                self._expiry.pop(key, None)

    def scan_iter(self, match):
        with self._lock:
            return [k for k in list(self._data) if fnmatch.fnmatch(k, match)]

    def ping(self):
        return True


def connect(url=None):
    url = url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    if url.startswith("memory://"):
        return MemoryStore()
    import redis
    client = redis.Redis.from_url(url, decode_responses=True)
    try:
        client.ping()
    except redis.exceptions.ConnectionError as exc:
        raise SystemExit(
            f"Cannot reach Redis at {url} ({exc}).\n"
            "Start it with `docker compose up -d --wait`, or run without Docker:\n"
            "    REDIS_URL=memory:// python app.py")
    return client


class Counters:
    """The handful of counters the layers need, all namespaced and windowed."""

    def __init__(self, backend):
        self.r = backend

    def _k(self, *parts):
        return PREFIX + ":".join(str(p) for p in parts)

    def bump(self, *parts):
        """Increment a windowed counter and return the new value."""
        key = self._k(*parts)
        value = self.r.incr(key)
        if value == 1:
            self.r.expire(key, WINDOW_S)
        return value

    def add_distinct(self, member, *parts):
        """Add `member` to a windowed set and return how many distinct members it has."""
        key = self._k(*parts)
        self.r.sadd(key, member)
        self.r.expire(key, WINDOW_S)
        return self.r.scard(key)

    def hbump(self, field, *parts, amount=1):
        key = self._k(*parts)
        self.r.hincrby(key, field, amount)
        self.r.expire(key, WINDOW_S)

    def hget_all(self, *parts):
        return {k: int(v) for k, v in self.r.hgetall(self._k(*parts)).items()}

    def put(self, value, *parts, ttl=WINDOW_S):
        self.r.set(self._k(*parts), value, ex=ttl)

    def fetch(self, *parts):
        return self.r.get(self._k(*parts))

    def drop(self, *parts):
        self.r.delete(self._k(*parts))

    def reset(self):
        """Delete only this lab's keys, never the whole database."""
        keys = list(self.r.scan_iter(match=PREFIX + "*"))
        if keys:
            self.r.delete(*keys)
        return len(keys)
