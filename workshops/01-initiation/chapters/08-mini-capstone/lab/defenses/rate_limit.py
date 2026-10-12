"""
W1 Ch8 — Layer: rate limiting with Redis token buckets (W1 Ch1).

Three buckets, checked in order of cost:
    ip           every request from one source IP
    prefix       every request from one /24 (IPv4) or /64 (IPv6)
    checkout_ip  POST /checkout from one source IP

A token bucket allows a burst (capacity) and then a sustained rate (refill
per second). The check-and-take runs as one Lua script, so concurrent
requests can't both spend the last token.

What it catches: volume from a few addresses (wave 0's hammering).
What it misses: anything spread over many addresses (waves 1-4 send one or
two requests per IP). It is the cheapest layer, so it runs first.
False positives: shared IPs. Eight phones behind one carrier-grade NAT
address spend one bucket. Tighten `checkout_ip` on Drop Day and watch the
mobile_cgnat shoppers in the scoreboard.

Run standalone to see a bucket drain:
    REDIS_URL=fakeredis:// python defenses/rate_limit.py
"""

import ipaddress
import time

import policy
from ladder import Signal

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


def take(redis, bucket, key):
    """Take one token from `bucket` for `key`. Returns True if allowed."""
    capacity, refill = policy.RATE_LIMITS[bucket]
    script = _scripts.get(id(redis))
    if script is None:
        script = _scripts[id(redis)] = redis.register_script(TOKEN_BUCKET_LUA)
    return bool(script(keys=[f"rl:{bucket}:{key}"], args=[capacity, refill, time.time()]))


def prefix_of(ip):
    """The /24 (IPv4) or /64 (IPv6) an address belongs to."""
    addr = ipaddress.ip_address(ip)
    bits = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{bits}", strict=False))


def check(ctx):
    """Layer entry point: one Signal named rate_limited, or nothing."""
    buckets = [("ip", ctx.ip), ("prefix", prefix_of(ctx.ip))]
    if ctx.method == "POST" and ctx.path == "/checkout":
        buckets.append(("checkout_ip", ctx.ip))
    for bucket, key in buckets:
        if not take(ctx.redis, bucket, key):
            return [Signal("rate_limit", "rate_limited", 0, f"{bucket} bucket empty for {key}")]
    return []


if __name__ == '__main__':
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from store import get_redis

    r = get_redis()
    capacity, refill = policy.RATE_LIMITS["checkout_ip"]
    print(f"checkout_ip bucket: capacity {capacity}, refill {refill}/s")
    r.delete("rl:checkout_ip:198.51.100.7")
    results = [take(r, "checkout_ip", "198.51.100.7") for _ in range(capacity + 3)]
    print("  " + " ".join("✅" if ok else "⛔" for ok in results))
    print(f"  {sum(results)} allowed, {len(results) - sum(results)} refused in a burst of {len(results)}")
