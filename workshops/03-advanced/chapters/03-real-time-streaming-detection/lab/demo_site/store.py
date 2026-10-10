"""
W3 Ch3 — Shared store (real Redis, or fakeredis without Docker)

Every detector in this chapter keeps state that must be identical on every
worker: sliding-window counters, per-session timing, and the probabilistic
sketches (Count-Min, HyperLogLog, Top-K). In production that state lives in
Redis 8 (or Valkey), never in one process. This module hands you a client and
nothing else decides where the state lives.

    REDIS_URL=memory://                  in-process fallback (fakeredis) — the default
    REDIS_URL=redis://localhost:6379/0   a real Redis 8 from ../docker-compose.yml

Why Redis Streams and not Kafka here: the demo store is already Flask + Redis.
Redis Streams give us an append-only log (XADD), consumer groups with
acknowledgements and lag (XREADGROUP / XACK / XINFO), and the probabilistic
commands live in the same server. That is the whole streaming toolkit on one
dependency a laptop already has. Kafka, Faust, Flink and Redpanda are the
scale-out answer and we discuss them on a slide, not in the lab — Redpanda is
not open source (BSL), and a six-broker JVM topology is not a laptop exercise.

Trade-offs you will measure:
- memory:// is a single process. The Flask app runs its consumer in a thread
  so the fallback works end to end; a *separate* consumer process needs real
  Redis so the two share a server. The checkpoint runs in one process, so it
  is happy on memory://.
- Count-Min and Top-K are built into Redis 8 core. On older Redis you needed
  the RedisBloom module; fakeredis ships them under its `probabilistic` extra.
"""

import os


def connect(url=None):
    """Return a Redis-compatible client. decode_responses=True everywhere."""
    url = url or os.environ.get("REDIS_URL", "memory://")
    if url.startswith("memory://"):
        import fakeredis
        return fakeredis.FakeStrictRedis(decode_responses=True)
    import redis
    client = redis.Redis.from_url(url, decode_responses=True)
    try:
        client.ping()
    except redis.exceptions.ConnectionError as exc:
        raise SystemExit(
            f"Cannot reach Redis at {url} ({exc}).\n"
            "Start it with `docker compose up -d --wait`, or run without Docker:\n"
            "    REDIS_URL=memory:// python demo_site/app.py")
    return client
