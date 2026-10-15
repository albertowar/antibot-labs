"""
Round 5 (level 5) - HMAC request signing.

A bearer token alone is a bearer instrument: whoever holds it can use it. Harvest one - from a man-in-the-middled
mobile session (W3 Ch1), a leaked log, an infostealer (W2 Ch6) - and you can replay it from anywhere. Signing
binds each request to a secret the first-party client holds and never transmits, so holding the token is not
enough; you must also be able to sign.

At login the server issues, alongside the bearer token, a per-token signing secret delivered once over the
authenticated channel (``api_secret``). Every protected request carries ``X-Timestamp`` and ``X-Signature``,
where the signature is HMAC-SHA256(secret) over a canonical string of method, path-and-query, timestamp and a
hash of the body. The server recomputes it and rejects a missing, malformed, stale or mismatched signature. A
replayed bearer token with no secret cannot produce a valid signature, and the timestamp plus a short skew
window stops signature replay.

This is request signing as AWS SigV4 and many mobile APIs do it. It is not a bot detector; it is an
authentication hardening that makes a stolen token far less useful. It pairs with token binding
(token_binding.py: coarse client signals, shipped done) - layers, not substitutes: binding catches a replay even
when the attacker omits signing entirely, and signing catches a replay even when the attacker spoofs the coarse
client signals. ``sign`` and ``_check`` ship done; ``verify`` is yours.

Where it runs: the protected /api/v2/ reads call the ladder in the phases ``action:api2_orders`` and
``action:api2_inventory``, so this check (phases ``action:api2_*``) runs on those two reads only.

False positives: clock skew is the classic one - a client with a wrong clock fails the timestamp check, so size
the window for real-world drift (a few minutes), and return a clear, retryable error. Secret rotation must be
handled (accept the previous secret for a grace period) or every in-flight request fails at rotation.
"""

import hashlib
import hmac

from .pipeline import Check, Signal

MAX_SKEW_S = 300
BLOCK_POINTS = 80          # policy blocks at >= 75


def canonical(method, path, ts, body):
    body_hash = hashlib.sha256(body or b"").hexdigest()
    return f"{method.upper()}\n{path}\n{ts}\n{body_hash}"


def sign(secret, method, path, ts, body):
    msg = canonical(method, path, ts, body).encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


class _Headers(dict):
    """Case-insensitive lookup over the request headers."""

    def get(self, name, default=None):
        return super().get(name.lower(), default)


def verify(method, path, headers, body, secret, now):
    """Return (points, reasons). Zero points means a valid signature."""
    # >>> SOLUTION round5 (verify the HMAC signature and timestamp)
    sig, ts = headers.get("X-Signature", ""), headers.get("X-Timestamp", "")
    if not sig or not ts:
        return BLOCK_POINTS, ["missing signature: X-Signature and X-Timestamp are required"]
    try:
        skew = abs(now - float(ts))
    except ValueError:
        return BLOCK_POINTS, ["malformed timestamp: X-Timestamp is not a number"]
    if skew > MAX_SKEW_S:
        return BLOCK_POINTS, [f"stale signature: {int(skew)}s skew (max {MAX_SKEW_S}s)"]
    if not secret:
        return BLOCK_POINTS, ["no signing secret: this token carries none"]
    if not hmac.compare_digest(sign(secret, method, path, ts, body), sig):
        return BLOCK_POINTS, ["invalid signature: the request does not match its signature"]
    return 0, []
    # <<< SOLUTION round5


def _check(ctx):
    bearer = ctx.attrs.get("bearer")
    headers = _Headers((k.lower(), v) for k, v in ctx.headers)
    points, reasons = verify(ctx.method, ctx.attrs["target"], headers, ctx.attrs["body"],
                             bearer["secret"] if bearer else "", ctx.attrs["now"])
    if not points:
        return None
    ctx.note(signing_reasons=reasons)
    return tuple(Signal("request_signing", r.split(":")[0].replace(" ", "_"), points if i == 0 else 0, r)
                 for i, r in enumerate(reasons))


CHECK = Check("request_signing", _check, phases=("action:api2_*",))
