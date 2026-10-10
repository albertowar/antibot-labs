"""L5 — HMAC request signing (Round 5).

A bearer token alone is a bearer instrument: whoever holds it can use it. Harvest
one — from a man-in-the-middled mobile session (W3 Ch1), a leaked log, an
infostealer (W2 Ch6) — and you can replay it from anywhere. Signing binds each
request to a secret the first-party client holds and never transmits, so holding
the token is not enough; you must also be able to sign.

At login the server issues, alongside the bearer token, a per-session signing
secret delivered once over the authenticated channel. Every protected request
carries ``X-Timestamp`` and ``X-Signature``, where the signature is
HMAC-SHA256(secret) over a canonical string of method, path, timestamp and a hash
of the body. The server recomputes it and rejects a missing, malformed, stale or
mismatched signature. A replayed bearer token with no secret cannot produce a
valid signature, and the timestamp plus a short skew window stops signature replay.

This is request signing as AWS SigV4 and many mobile APIs do it. It is not a bot
detector; it is an authentication hardening that makes a stolen token far less
useful. Pair it with token binding (coarse client signals) so even a leaked
secret is constrained to the client it was issued to.

False positives: clock skew is the classic one — a client with a wrong clock
fails the timestamp check, so size the window for real-world drift (a few
minutes), and return a clear, retryable error. Secret rotation must be handled
(accept the previous secret for a grace period) or every in-flight request fails
at rotation.
"""

from __future__ import annotations

import hashlib
import hmac

MAX_SKEW_S = 300
BLOCK_POINTS = 60


def canonical(method: str, path: str, ts: str, body: bytes) -> str:
    body_hash = hashlib.sha256(body or b"").hexdigest()
    return f"{method.upper()}\n{path}\n{ts}\n{body_hash}"


def sign(secret: str, method: str, path: str, ts: str, body: bytes) -> str:
    msg = canonical(method, path, ts, body).encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify(method: str, path: str, headers, body: bytes, secret: str, now: float) -> tuple[int, list[str]]:
    """Return (points, reasons). Zero points means a valid signature."""
    # TODO (Round 5): verify the HMAC signature and timestamp.
    #   - require X-Signature and X-Timestamp;
    #   - reject a skew > MAX_SKEW_S;
    #   - recompute sign(secret, method, path, ts, body) and compare with
    #     hmac.compare_digest. Return (BLOCK_POINTS, [reason]) on failure.
    # Catch up with: python tools/checkpoint.py --round 5 --catch-up
    return 0, []
