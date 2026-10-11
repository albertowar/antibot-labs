"""Shared store: real Redis, or fakeredis in-process so the lab needs no Docker.

The gate keeps three kinds of state that every worker must share: crawl budgets
(per lane, per identity or IP), verification caches (reverse-DNS verdicts, range
files, key directories) and the nonce replay cache from Round 4. All of it lives in
Redis in production; here `REDIS_URL=memory://` (the default) swaps in fakeredis so
one process is enough.

    REDIS_URL=memory://                  in-process fakeredis (default)
    REDIS_URL=redis://localhost:6379/0   a Redis you run yourself
"""

import os


def connect(url=None):
    url = url or os.environ.get("REDIS_URL", "memory://")
    if url.startswith("memory://"):
        import fakeredis
        return fakeredis.FakeStrictRedis(decode_responses=True)
    import redis
    client = redis.Redis.from_url(url, decode_responses=True)
    try:
        client.ping()
    except redis.exceptions.ConnectionError as exc:
        raise SystemExit(f"Cannot reach Redis at {url} ({exc}). Run without it: REDIS_URL=memory://")
    return client
