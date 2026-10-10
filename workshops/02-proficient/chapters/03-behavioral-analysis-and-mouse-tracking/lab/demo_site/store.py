"""
Chapter 3: session, trace and signature storage for the demo store.

Two back ends with the same interface:

    STORE=redis   (default) Redis from ../docker-compose.yml, REDIS_URL to override
    STORE=memory  plain dicts in the Flask process, for laptops without Docker

Trade-off: the memory store forgets everything when you restart the server
with a new DEFENSE_LEVEL. That matters in Round 4, where the replay defense
remembers path signatures across sessions: with Redis, a replay of a trace
the store has already seen is caught on its first use; with STORE=memory,
the first replay after a restart gets through. The checkpoint accepts both.
"""

import json
import os
import time
from collections import deque

SESSION_TTL_S = 30 * 60
TRACE_TTL_S = 24 * 3600
SIGNATURE_HISTORY = 2000      # how many recent session signatures L4 compares against
DECISION_HISTORY = 200


class MemoryStore:
    def __init__(self):
        self._sessions = {}
        self._traces = {}
        self._decisions = deque(maxlen=DECISION_HISTORY)
        self._signatures = deque(maxlen=SIGNATURE_HISTORY)

    def put_session(self, sid, data):
        self._sessions[sid] = (time.time() + SESSION_TTL_S, data)

    def pop_session(self, sid):
        """Sessions are single-use: a second reservation with the same sid fails."""
        expires, data = self._sessions.pop(sid, (0, None))
        return data if expires > time.time() else None

    def put_trace(self, sid, trace):
        self._traces[sid] = trace

    def get_trace(self, sid):
        return self._traces.get(sid)

    def add_decision(self, decision):
        self._decisions.appendleft(decision)

    def decisions(self, limit=30):
        return list(self._decisions)[:limit]

    def add_signature(self, sid, signature):
        self._signatures.appendleft([sid, signature])

    def recent_signatures(self):
        return list(self._signatures)


class RedisStore:
    def __init__(self, url):
        import redis   # imported here so STORE=memory works without the package
        self.r = redis.Redis.from_url(url, decode_responses=True)
        self.r.ping()

    def put_session(self, sid, data):
        self.r.set(f"drop:session:{sid}", json.dumps(data), ex=SESSION_TTL_S)

    def pop_session(self, sid):
        raw = self.r.getdel(f"drop:session:{sid}")
        return json.loads(raw) if raw else None

    def put_trace(self, sid, trace):
        self.r.set(f"behavior:trace:{sid}", json.dumps(trace), ex=TRACE_TTL_S)

    def get_trace(self, sid):
        raw = self.r.get(f"behavior:trace:{sid}")
        return json.loads(raw) if raw else None

    def add_decision(self, decision):
        pipe = self.r.pipeline()
        pipe.lpush("behavior:decisions", json.dumps(decision))
        pipe.ltrim("behavior:decisions", 0, DECISION_HISTORY - 1)
        pipe.execute()

    def decisions(self, limit=30):
        return [json.loads(d) for d in self.r.lrange("behavior:decisions", 0, limit - 1)]

    def add_signature(self, sid, signature):
        pipe = self.r.pipeline()
        pipe.lpush("behavior:signatures", json.dumps([sid, signature]))
        pipe.ltrim("behavior:signatures", 0, SIGNATURE_HISTORY - 1)
        pipe.execute()

    def recent_signatures(self):
        return [json.loads(s) for s in self.r.lrange("behavior:signatures", 0, -1)]


def open_store():
    kind = os.environ.get("STORE", "redis")
    if kind == "memory":
        return MemoryStore()
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    try:
        return RedisStore(url)
    except Exception as exc:   # connection refused, package missing, ...
        raise SystemExit(
            f"Cannot reach Redis at {url} ({exc}).\n"
            "Start it with `docker compose up -d --wait`, or run without Docker: STORE=memory"
        ) from exc
