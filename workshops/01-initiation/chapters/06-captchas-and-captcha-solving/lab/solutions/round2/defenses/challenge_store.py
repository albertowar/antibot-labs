"""
Chapter 6, Round 2 REFERENCE SOLUTION (python tools/checkpoint.py --round 2 --catch-up installs it).

defenses/captcha_gate.py calls issue() when the store serves a `captcha` challenge and check()
when the client answers it (POST /api/challenge/verify).

The shipped version kept the answer in a signed cookie: signed is not encrypted, and nothing was
consumed, so one challenge became twenty vouchers. This version keeps the answer in Redis (the
store's own, ctx.redis) and it is:
  - never sent to the client      - single use (GETDEL)
  - bound to the session          - short-lived (TTL)
  - limited to MAX_ATTEMPTS wrong answers

Trade-off: server-side state costs one Redis write per challenge and one round trip per check.
That is the price of being able to say "used".

It records who fetched the challenge (issuer IP and User-Agent) and when. Round 4 uses that.

`ctx` is the request's Ctx (defenses/context.py): ctx.redis, ctx.ip, ctx.ua.raw, ctx.session.sid.
Try it on its own:  python -m defenses.challenge_store
"""

import hmac
import json
import math
import secrets
import time

from . import policy

COOKIE_NAME = "captcha"
MAX_ATTEMPTS = 3


def _key(challenge_id):
    return f"lab:captcha:{challenge_id}"


def _ttl():
    """Real seconds a challenge lives: policy.CAPTCHA_TTL_SIM_S simulated seconds."""
    return max(1, math.ceil(policy.CAPTCHA_TTL_SIM_S / policy.TIME_SCALE))


def issue(ctx, answer):
    """Store a new challenge. Returns (challenge_id, cookie_value or None)."""
    challenge_id = secrets.token_urlsafe(12)
    record = {"id": challenge_id, "answer": answer, "issued_at": time.time(),
              "issuer_ip": ctx.ip, "issuer_ua": ctx.ua.raw}
    record.update(session_id=ctx.session.sid, attempts=0)
    ctx.redis.set(_key(challenge_id), json.dumps(record), ex=_ttl())
    return challenge_id, None            # nothing about the answer reaches the client


def check(ctx, challenge_id, submitted, cookie):
    """Verify an answer. Returns (ok, reason, record or None)."""
    if not challenge_id:
        return False, "no challenge", None
    # GETDEL is atomic: two concurrent submissions cannot both see the record.
    raw = ctx.redis.getdel(_key(challenge_id))
    if raw is None:
        return False, "unknown, expired or already used challenge", None
    record = json.loads(raw)

    if record["session_id"] != ctx.session.sid:
        return False, "challenge belongs to another session", record

    if hmac.compare_digest(submitted.strip().upper(), record["answer"]):
        return True, "correct", record

    record["attempts"] += 1
    if record["attempts"] < MAX_ATTEMPTS:
        remaining = _ttl() - (time.time() - record["issued_at"])
        if remaining > 0:
            ctx.redis.set(_key(challenge_id), json.dumps(record), ex=math.ceil(remaining))
    return False, "wrong answer", record


if __name__ == "__main__":
    from types import SimpleNamespace

    from . import store

    def client(sid):
        return SimpleNamespace(redis=store.get_redis("memory://"), ip="192.0.2.77",
                               ua=SimpleNamespace(raw="demo"), session=SimpleNamespace(sid=sid))
    ctx = client("s1")
    cid, cookie = issue(ctx, "K7PQX")
    print(f"issued {cid}; cookie sent to the client: {cookie}")
    print("first check:  ", check(ctx, cid, "K7PQX", cookie)[:2])
    print("replayed:     ", check(ctx, cid, "K7PQX", cookie)[:2])
    cid, cookie = issue(ctx, "K7PQX")
    other = client("s2")
    other.redis = ctx.redis
    print("other session:", check(other, cid, "K7PQX", cookie)[:2])
