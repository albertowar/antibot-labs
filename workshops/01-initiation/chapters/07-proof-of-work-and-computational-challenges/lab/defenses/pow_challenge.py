"""
Chapter 7: issuing and verifying the `pow` challenge, one scheme per level.

demo_site/ext/pow.py registers issue() and verify() with the store's challenge hook; this
module is what they call. The scheme follows the defense level, so DEFENSE_LEVEL (or
`checkpoint.py --round N`) is the switch between rounds:

    L1  naive    challenge_naive: the server trusts the difficulty the client sends back
    L2  signed   challenge_signed: HMAC over nonce, difficulty, expiry and client IP
    L3  single-use: the signed challenge's nonce can be redeemed once (Redis SET NX), and
                 a verified answer starts a pass bound to this IP + User-Agent (pow_budget.py)
    L4  adaptive: issue() reads the price from ctx.attrs["pow_bits"] (pow_adaptive.py)

Why a Redis SET NX and not a Python set: with several workers a nonce could be spent once
per worker. Spend AFTER verifying the signature, or anyone could burn other clients' nonces.

Why verify() only returns a bool: the store's challenge API answers `challenge_failed` and
nothing else, as production should. The reason goes to the decision log
(`GET /lab/decisions`, field extra.pow_reason) for the lab to read, never to the client.
"""

import os
import time

from . import challenge_naive, challenge_signed, policy
from .pow_budget import client_tag

# Restarting the store rotates the secret, which invalidates challenges in flight. Fine for a lab.
SECRET = os.environ.setdefault("POW_SECRET", os.urandom(32).hex()).encode()


def _bind(ctx):
    return challenge_signed.client_bind(ctx.ip)


def issue(ctx):
    bits = ctx.attrs.get("pow_bits", policy.POW_BASE_BITS)
    if ctx.level <= 1:
        return challenge_naive.issue(bits)
    return challenge_signed.issue(SECRET, bits, _bind(ctx))


def verify(ctx, answer):
    challenge, counter = answer.get("challenge") or {}, answer.get("counter")
    if not isinstance(challenge, dict):
        challenge = {}
    if ctx.level <= 1:
        ok, reason = challenge_naive.verify(challenge, counter)
    else:
        ok, reason = challenge_signed.verify(SECRET, challenge, counter, _bind(ctx))
    if ok and ctx.level >= 3:
        spent = ctx.redis.set(f"lab:pow:spent:{challenge['nonce']}", 1, nx=True, ex=challenge_signed.CHALLENGE_TTL)
        if not spent:
            ok, reason = False, "[L3] challenge already redeemed (replay)"
    ctx.note(pow_reason=reason, pow_bits=challenge.get("difficulty"))
    if ok and ctx.level >= 3:
        ctx.session.set("pow:bind", client_tag(ctx))
        ctx.redis.delete(ctx.session.ns("pow") + "used")
    return ok
