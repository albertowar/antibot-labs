"""
W1 Ch8 — Shared connections for the defense layers.

    REDIS_URL=redis://localhost:6379/0   the default (docker compose)
    REDIS_URL=fakeredis://               no Docker: an in-process Redis (lab only)

The in-process fallback only works because the store is the only process
that talks to Redis. It loses all state on restart, which is fine for a lab
and useless in production.
"""

import os

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

_client = None


def get_redis():
    global _client
    if _client is None:
        if REDIS_URL.startswith("fakeredis://"):
            import fakeredis
            _client = fakeredis.FakeRedis(decode_responses=True)
        else:
            import redis
            _client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    return _client
