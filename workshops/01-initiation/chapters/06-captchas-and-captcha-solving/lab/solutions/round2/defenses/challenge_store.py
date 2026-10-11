"""
Chapter 6 — Where the CAPTCHA answer lives (Section 6.3, Round 2)

REFERENCE SOLUTION for Round 2 (tools/checkpoint.py --round 2 --catch-up installs it).

The answer lives in Redis (the server-side store from Chapter 5) and is:
  - never sent to the client      - single use (GETDEL)
  - bound to the session          - short-lived (TTL)
  - limited to MAX_ATTEMPTS wrong answers

The shipped version put the answer in a signed cookie. Signed is not
encrypted, and nothing was ever consumed: one solve verified forever.

Trade-off: server-side state costs one Redis write per challenge and one
round trip per check. That is the price of being able to say "used".

The record keeps who fetched the challenge (issuer IP and User-Agent) and
when. Round 4 uses that.
"""

import hmac
import json
import math
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from labkit import TIME_SCALE  # noqa: E402

COOKIE_NAME = "captcha"
TTL_SIM_S = 120          # simulated seconds a challenge stays valid
MAX_ATTEMPTS = 3


def _key(challenge_id):
    return f"captcha:{challenge_id}"


def _ttl():
    return max(1, math.ceil(TTL_SIM_S / TIME_SCALE))


def issue(redis, answer, ctx):
    """Store a new challenge. Returns (challenge_id, cookie_value or None).

    ctx = {"session_id", "ip", "ua"} describes the client fetching the image.
    """
    challenge_id = secrets.token_urlsafe(12)
    record = {"id": challenge_id, "answer": answer, "issued_at": time.time(),
              "issuer_ip": ctx["ip"], "issuer_ua": ctx["ua"],
              "session_id": ctx["session_id"], "attempts": 0}
    redis.set(_key(challenge_id), json.dumps(record), ex=_ttl())
    return challenge_id, None


def check(redis, challenge_id, submitted, ctx, cookie):
    """Verify an answer. Returns (ok, reason, record or None)."""
    if not challenge_id:
        return False, "no challenge", None
    # GETDEL is atomic: two concurrent submissions cannot both see the record.
    raw = redis.getdel(_key(challenge_id))
    if raw is None:
        return False, "unknown, expired or already used challenge", None
    record = json.loads(raw)

    if record["session_id"] != ctx["session_id"]:
        return False, "challenge belongs to another session", record

    if hmac.compare_digest(submitted.strip().upper(), record["answer"]):
        return True, "correct", record

    record["attempts"] += 1
    if record["attempts"] < MAX_ATTEMPTS:
        remaining = _ttl() - (time.time() - record["issued_at"])
        if remaining > 0:
            redis.set(_key(challenge_id), json.dumps(record), ex=math.ceil(remaining))
    return False, "wrong answer", record


if __name__ == "__main__":
    import redis as redis_lib
    from labkit import REDIS_URL
    r = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
    ctx = {"session_id": "s1", "ip": "198.51.100.7", "ua": "demo"}
    cid, cookie = issue(r, "K7PQX", ctx)
    print(f"issued {cid}; cookie sent to the client: {cookie}")
    print("first check: ", check(r, cid, "K7PQX", ctx, cookie)[:2])
    print("replayed:    ", check(r, cid, "K7PQX", ctx, cookie)[:2])
    cid, cookie = issue(r, "K7PQX", ctx)
    print("other session:", check(r, cid, "K7PQX", {**ctx, "session_id": "s2"}, cookie)[:2])
