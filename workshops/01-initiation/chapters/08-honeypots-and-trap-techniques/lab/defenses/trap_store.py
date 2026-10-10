"""
Chapter 8 — Trap Store (Section 8.4)

Every trap hit becomes an event, and every sanction is a Redis key with a TTL.
The demo store's accounts and reviews live here too, so one service backs the
whole lab.

Keys:
    trap:events                capped list of JSON events, newest first (/trap-logs)
    sanction:ip:<ip>           reason; expires after SANCTION_TTL
    sanction:sid:<session id>  reason; expires after SANCTION_TTL
    acct:<username>            hash: password, status (active | quarantined)
    reviews:<product id>       list of JSON reviews
    lab:actor:<actor>          scoreboard counters, keyed by the X-Lab-Actor label
    lab:timings                capped list of trap-check durations in ms

Trade-offs:
  - Sanctions expire. A permanent block list grows forever, and the IPs on it
    get reassigned to real customers (DHCP, CGNAT, mobile carriers). Fifteen
    minutes is enough to make a bot start over, and short enough that a false
    positive heals itself.
  - Events are capped at EVENTS_MAX. In production you'd ship them to your log
    pipeline rather than keep them in Redis.
  - `lab:actor:*` exists only for the scoreboard. No defense reads it.

Set REDIS_URL=memory:// to run without Docker (in-process fakeredis). The
store then lives inside the Flask process and is wiped on every restart.
"""

import json
import os
import time

import redis

SANCTION_TTL = 15 * 60
EVENTS_MAX = 500
TIMINGS_MAX = 2000


def connect():
    url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    if url.startswith("memory://"):
        import fakeredis
        return fakeredis.FakeRedis(decode_responses=True)
    return redis.Redis.from_url(url, decode_responses=True)


r = connect()


# --- Trap events and sanctions ------------------------------------------------

def record_event(actor, ip, sid, trap, path, detail=""):
    """Log one trap hit and count it for the scoreboard."""
    event = {
        "ts": round(time.time(), 3), "actor": actor, "ip": ip, "sid": sid,
        "trap": trap, "path": path, "detail": detail,
    }
    pipe = r.pipeline()
    pipe.lpush("trap:events", json.dumps(event))
    pipe.ltrim("trap:events", 0, EVENTS_MAX - 1)
    pipe.hincrby(f"lab:actor:{actor}", f"trap:{trap}", 1)
    pipe.execute()


def recent_events(limit=50):
    return [json.loads(e) for e in r.lrange("trap:events", 0, limit - 1)]


def sanction(key_type, value, reason):
    """Sanction an IP or a session for SANCTION_TTL seconds."""
    r.set(f"sanction:{key_type}:{value}", reason, ex=SANCTION_TTL)


def sanctioned(key_type, value):
    """Return the sanction reason, or None."""
    return r.get(f"sanction:{key_type}:{value}")


# --- Accounts and reviews -----------------------------------------------------

def create_account(username, password, status="active"):
    """Create the account. Returns False if the username is taken."""
    if r.exists(f"acct:{username}"):
        return False
    # Plain-text passwords are acceptable ONLY because every account is synthetic.
    r.hset(f"acct:{username}", mapping={"password": password, "status": status})
    return True


def get_account(username):
    return r.hgetall(f"acct:{username}") or None


def add_review(product_id, author, text, published):
    review = {"author": author, "text": text, "published": published}
    r.rpush(f"reviews:{product_id}", json.dumps(review))


def reviews_for(product_id):
    return [json.loads(x) for x in r.lrange(f"reviews:{product_id}", 0, -1)]


# --- Scoreboard instrumentation -----------------------------------------------

def count(actor, field, n=1):
    r.hincrby(f"lab:actor:{actor}", field, n)


def add_timing(ms):
    pipe = r.pipeline()
    pipe.lpush("lab:timings", f"{ms:.4f}")
    pipe.ltrim("lab:timings", 0, TIMINGS_MAX - 1)
    pipe.execute()


def summary():
    """Per-actor counters plus raw trap-check timings, for tools/checkpoint.py."""
    actors = {}
    for key in r.scan_iter("lab:actor:*"):
        actors[key.split(":", 2)[2]] = {k: int(v) for k, v in r.hgetall(key).items()}
    timings = [float(t) for t in r.lrange("lab:timings", 0, -1)]
    return {"actors": actors, "timings_ms": timings}


def reset():
    """Wipe everything this lab stores. Debug endpoint only."""
    for pattern in ("trap:*", "sanction:*", "acct:*", "reviews:*", "lab:*"):
        keys = list(r.scan_iter(pattern))
        if keys:
            r.delete(*keys)


if __name__ == "__main__":
    reset()
    record_event("demo", "203.0.113.10", "abc123", "honeypot_field", "/register")
    sanction("ip", "203.0.113.10", "honeypot_field")
    print("sanctioned 203.0.113.10:", sanctioned("ip", "203.0.113.10"))
    print("sanctioned 203.0.113.11:", sanctioned("ip", "203.0.113.11"))
    print("events:", recent_events())
    reset()
