"""Shared datastore for the W3 Ch2 API demo store.

Two backends, chosen by environment variables, so the lab runs on a bare laptop
*and* in a production-shaped stack:

  * Redis -> a real server when REDIS_URL is set, otherwise an in-process
             ``fakeredis`` instance. The demo site is the only process that
             touches Redis (velocity counters, per-connection WebSocket buckets,
             persisted-query cache), so fakeredis — which lives only in this
             process — is enough. Attackers and the simulator talk to us over
             HTTP/WS, never to Redis directly.
  * SQL   -> PostgreSQL when DATABASE_URL is set, otherwise a local SQLite file.
             Both the app and the tools read the decision log, so it must be a
             *shared* store; SQLite is a file on disk, which is why the log lives
             in SQL and not in Redis.

Nothing here is bot-detection logic. It is the plumbing the defense modules and
the three API surfaces (REST, GraphQL, WebSocket) build on. The trade-off it
encodes: a dependency-free default (fakeredis + SQLite) that any laptop can run
in under a minute, with one environment variable each to swap in the real thing.
"""

from __future__ import annotations

import os


def make_redis():
    """Return a Redis client, or an in-process fakeredis when no server is set.

    fakeredis keeps the lab dependency-free, but its state is per process and
    vanishes on restart. That is exactly what we want between rounds: each round
    restarts the server with a clean slate, and the attack/legit tooling never
    needs Redis because it drives the app over HTTP and WebSocket.
    """
    url = os.environ.get("REDIS_URL")
    if url:
        import redis  # imported lazily so the lab installs without a server
        return redis.Redis.from_url(url, decode_responses=True)
    import fakeredis
    return fakeredis.FakeStrictRedis(decode_responses=True)
