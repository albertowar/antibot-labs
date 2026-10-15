"""
Shared Redis helpers for every defense.

    REDIS_URL=memory://                   default: in-process fakeredis (single process, lab only)
    REDIS_URL=redis://localhost:6379/0    docker compose

The in-process fallback loses all state on restart and only works because the
store is the one process talking to it. Production uses the real thing.
"""

import ipaddress
import os
import time

_client = None

TOKEN_BUCKET_LUA = """
local key      = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill   = tonumber(ARGV[2])
local now      = tonumber(ARGV[3])
local state  = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1]) or capacity
local ts     = tonumber(state[2]) or now
tokens = math.min(capacity, tokens + (now - ts) * refill)
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
redis.call('HSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, math.ceil(capacity / refill) + 1)
return allowed
"""
_scripts = {}


def get_redis(url=None):
    global _client
    if _client is None:
        url = url or os.environ.get("REDIS_URL", "memory://")
        if url.startswith(("memory://", "fakeredis://")):
            import fakeredis
            _client = fakeredis.FakeStrictRedis(decode_responses=True)
        else:
            import redis
            _client = redis.Redis.from_url(url, decode_responses=True)
    return _client


def token_bucket(redis, bucket, key, limits=None):
    """Take one token from `bucket` for `key`. Atomic in Lua. True if allowed."""
    from . import policy
    capacity, refill = (limits or policy.RATE_LIMITS)[bucket]
    script = _scripts.get(id(redis))
    if script is None:
        script = _scripts[id(redis)] = redis.register_script(TOKEN_BUCKET_LUA)
    return bool(script(keys=[f"lab:rl:{bucket}:{key}"], args=[capacity, refill, time.time()]))


def prefix_of(ip):
    """The /24 (IPv4) or /64 (IPv6) an address belongs to: the unit of cheap rotation."""
    addr = ipaddress.ip_address(ip)
    bits = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{bits}", strict=False))


class Counters:
    """Windowed counters: how many times did `key` do `event` in the last `window` seconds."""

    def __init__(self, redis, prefix="lab:c"):
        self.redis, self.prefix = redis, prefix

    def hit(self, event, key, window=60):
        k = f"{self.prefix}:{event}:{key}"
        now = time.time()
        p = self.redis.pipeline()
        p.zadd(k, {f"{now}": now})
        p.zremrangebyscore(k, 0, now - window)
        p.zcard(k)
        p.expire(k, window + 1)
        return p.execute()[2]

    def count(self, event, key, window=60):
        k = f"{self.prefix}:{event}:{key}"
        now = time.time()
        self.redis.zremrangebyscore(k, 0, now - window)
        return self.redis.zcard(k)


def flush_lab_state(redis):
    for k in redis.scan_iter("lab:*"):
        redis.delete(k)
