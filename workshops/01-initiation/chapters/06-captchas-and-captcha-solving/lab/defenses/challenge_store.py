"""
Chapter 6, Round 2: where the CAPTCHA answer lives (section 6.3).

defenses/captcha_gate.py calls issue() when the store serves a `captcha` challenge and check()
when the client answers it (POST /api/challenge/verify).

As shipped, this is the "stateless" design that looks clever in a code review: the answer goes
into a signed cookie, so no server storage is needed and any app server can verify it. It has
two flaws:

  1. Signed is not encrypted. itsdangerous (the library behind Flask's old default session
     cookie) base64-encodes the JSON payload; anyone can read the answer without solving anything.
  2. Nothing is consumed. The same cookie + answer pair verifies again and again, from any
     session, until it expires.

attacks/round2_cookie_replay.py turns one challenge into twenty vouchers.

Your job in Round 2: fix every TODO (Round 2) so that the answer lives in Redis (the
store's own Redis, ctx.redis) and is:
  - never sent to the client      - single use (GETDEL)
  - bound to the session          - short-lived (TTL)
  - limited to MAX_ATTEMPTS wrong answers

Trade-off: server-side state costs one Redis write per challenge and one round trip per check.
That is the price of being able to say "used".

Both versions record who fetched the challenge (issuer IP and User-Agent) and when.
Round 4 (solver_signals.py) uses that.

`ctx` is the request's Ctx (defenses/context.py): ctx.redis, ctx.ip, ctx.ua.raw, ctx.session.sid.
Try it on its own:  python -m defenses.challenge_store
"""

import hmac
import json
import math
import os
import secrets
import time

from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import policy

COOKIE_NAME = "captcha"
MAX_ATTEMPTS = 3

_signer = URLSafeTimedSerializer(os.environ.get("CAPTCHA_COOKIE_KEY", "dev-only-key"), salt="captcha")


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
    # TODO (Round 2): don't send the answer to the client. Store `record`
    #   (plus "session_id": ctx.session.sid and "attempts": 0) in Redis under
    #   _key(challenge_id) with an expiry of _ttl() seconds (ctx.redis.set(..., ex=...)),
    #   and return (challenge_id, None).
    return challenge_id, _signer.dumps(record)


def check(ctx, challenge_id, submitted, cookie):
    """Verify an answer. Returns (ok, reason, record or None)."""
    # TODO (Round 2): load the record from Redis instead of the cookie, and
    #   take it atomically with ctx.redis.getdel() so it can only be used once.
    try:
        record = _signer.loads(cookie or "", max_age=600)
    except BadSignature:
        return False, "no challenge", None

    # TODO (Round 2): reject if record["session_id"] != ctx.session.sid.
    # TODO (Round 2): on a wrong answer, put the record back with
    #   attempts + 1 (and its remaining TTL) unless attempts reached MAX_ATTEMPTS.
    if hmac.compare_digest(submitted.strip().upper(), record["answer"]):
        return True, "correct", record
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
