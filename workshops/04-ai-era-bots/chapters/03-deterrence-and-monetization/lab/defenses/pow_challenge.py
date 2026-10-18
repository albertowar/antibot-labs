"""Round 5 (given): issue and verify the `pow` challenge.

demo_site/ext/pow.py registers issue() and verify() with the store's challenge hook; this module is
what they call. The puzzle is W1 Ch7's, byte for byte (pow_core.py, challenge_signed.py; shared.json):
find a counter c so that SHA-256(f"{nonce}:{c}") has POW_BITS leading zero bits. A challenge is

  * signed    (HMAC over nonce, difficulty, expiry and the client address): a client cannot lower its
              own difficulty, W1 Ch7's Round 1 attack
  * bound     to the address it was issued to, so a solution cannot be sold to a solver farm elsewhere
  * expiring  after 60 s
  * single-use: a solved nonce is spent in Redis (SET NX), or one solution would buy unlimited passes

A verified answer makes the gate grant the session its clearance (the pass); `verify()` also records
what the pass is bound to (pow_gate.client_tag) and resets the pass's use counter, and
demo_site/ext/pow.py registers the type with a clearance lifetime of policy.POW_PASS_TTL.

The reason a verification failed goes to the decision log (`extra.pow_reason`), never to the client.
"""

import os

from . import challenge_signed, policy, pow_gate

# Restarting the store rotates the secret, which invalidates challenges in flight. Fine for a lab.
SECRET = os.environ.setdefault("POW_SECRET", os.urandom(32).hex()).encode()


def _bind(ctx):
    return challenge_signed.client_bind(ctx.ip)


def issue(ctx):
    return challenge_signed.issue(SECRET, policy.POW_BITS, _bind(ctx))


def verify(ctx, answer):
    challenge, counter = answer.get("challenge") or {}, answer.get("counter")
    if not isinstance(challenge, dict):
        challenge = {}
    ok, reason = challenge_signed.verify(SECRET, challenge, counter, _bind(ctx))
    if ok and not ctx.redis.set(f"lab:pow:spent:{challenge['nonce']}", 1, nx=True, ex=challenge_signed.CHALLENGE_TTL):
        ok, reason = False, "challenge already redeemed (replay)"
    ctx.note(pow_reason=reason, pow_bits=challenge.get("difficulty"))
    if ok:
        ctx.session.set("pow:bind", pow_gate.client_tag(ctx))
        ctx.redis.delete(ctx.session.ns("pow") + "used")
    return ok, reason
