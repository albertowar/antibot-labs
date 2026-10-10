"""
Chapter 6 — Where the CAPTCHA answer lives (Section 6.3, Round 2)

As shipped, this is the "stateless" design that looks clever in a code
review: the answer goes into a signed cookie, so no server storage is
needed and any app server can verify it. It has two flaws:

  1. Signed is not encrypted. itsdangerous (the library behind Flask's
     default session cookie) base64-encodes the JSON payload; anyone can
     read the answer without solving anything.
  2. Nothing is consumed. The same cookie + answer pair verifies again and
     again, from any session, until it expires.

attacks/round2_cookie_replay.py turns one challenge into twenty vouchers.

Your job in Round 2: fix every TODO (Round 2) so that the answer lives in
Redis (the server-side store you built in Chapter 5) and is:
  - never sent to the client      - single use (GETDEL)
  - bound to the session          - short-lived (TTL)
  - limited to MAX_ATTEMPTS wrong answers

Trade-off: server-side state costs one Redis write per challenge and one
round trip per check. That is the price of being able to say "used".

Both versions record who fetched the challenge (issuer IP and User-Agent)
and when. Round 4 uses that.
"""

import hmac
import json
import os
import secrets
import sys
import time

from itsdangerous import BadSignature, URLSafeTimedSerializer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from labkit import TIME_SCALE  # noqa: E402

COOKIE_NAME = "captcha"
TTL_SIM_S = 120          # simulated seconds a challenge stays valid
MAX_ATTEMPTS = 3

_signer = URLSafeTimedSerializer(os.environ.get("CAPTCHA_COOKIE_KEY", "dev-only-key"),
                                 salt="captcha")


def issue(redis, answer, ctx):
    """Store a new challenge. Returns (challenge_id, cookie_value or None).

    ctx = {"session_id", "ip", "ua"} describes the client fetching the image.
    """
    challenge_id = secrets.token_urlsafe(12)
    record = {"id": challenge_id, "answer": answer, "issued_at": time.time(),
              "issuer_ip": ctx["ip"], "issuer_ua": ctx["ua"]}
    # TODO (Round 2): don't send the answer to the client. Store `record`
    #   (plus ctx["session_id"] and attempts=0) in Redis under
    #   f"captcha:{challenge_id}" with an expiry of TTL_SIM_S / TIME_SCALE
    #   seconds, and return (challenge_id, None).
    return challenge_id, _signer.dumps(record)


def check(redis, challenge_id, submitted, ctx, cookie):
    """Verify an answer. Returns (ok, reason, record or None)."""
    # TODO (Round 2): load the record from Redis instead of the cookie, and
    #   take it atomically with redis.getdel() so it can only be used once.
    try:
        record = _signer.loads(cookie or "", max_age=600)
    except BadSignature:
        return False, "no challenge", None

    # TODO (Round 2): reject if record["session_id"] != ctx["session_id"].
    # TODO (Round 2): on a wrong answer, put the record back with
    #   attempts + 1 (and its remaining TTL) unless attempts reached MAX_ATTEMPTS.
    if hmac.compare_digest(submitted.strip().upper(), record["answer"]):
        return True, "correct", record
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
    print("other session:", check(r, cid, "K7PQX", {**ctx, "session_id": "s2"}, cookie)[:2])
