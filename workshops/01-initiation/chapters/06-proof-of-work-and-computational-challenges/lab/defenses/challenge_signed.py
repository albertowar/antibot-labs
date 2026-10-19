"""
Chapter 6 — Round 2 Defense (L2): a signed, expiring, bound challenge

The server still keeps no state, but it can now trust what comes back,
because it signs every field it cares about:

    sig = HMAC-SHA256(secret, "v1|nonce|difficulty|expires|bind")

  - difficulty:  the client cannot lower it without breaking the signature
  - expires:     a solution is only redeemable for CHALLENGE_TTL seconds
  - bind:        a hash of the client's IP, so a challenge solved by one
                 machine cannot be redeemed by another (e.g. a solver farm)

What this still allows (Round 2's attack): nothing stops the client from
redeeming the same solution several times before it expires, or from
reusing the pass it gets back for as many requests as it likes. Fixing
that needs server-side state (spend_store.py, Round 3).

Trade-off of binding to the IP: users whose IP changes mid-challenge
(mobile handover, dual-stack IPv4/IPv6, some corporate egress pools) fail
verification and must solve again. Keep CHALLENGE_TTL short so that is rare.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time

from .pow_core import MAX_BITS, digest, meets_difficulty

CHALLENGE_TTL = 60  # seconds to solve and redeem


def client_bind(*parts: str) -> str:
    """A short, non-reversible tag for 'this client' (IP, or IP + User-Agent)."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _sign(secret: bytes, *fields) -> str:
    msg = "|".join(str(f) for f in fields).encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def issue(secret: bytes, difficulty: int, bind: str, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    c = {"v": 1, "nonce": os.urandom(16).hex(), "difficulty": difficulty,
         "expires": int(now) + CHALLENGE_TTL, "bind": bind}
    c["sig"] = _sign(secret, "v1", c["nonce"], difficulty, c["expires"], bind)
    return c


def verify(secret: bytes, challenge: dict, counter, bind: str,
           now: float | None = None) -> tuple[bool, str]:
    """Verify signature, expiry, binding, then the hash. Cheapest checks first."""
    now = time.time() if now is None else now
    try:
        nonce, bits = str(challenge["nonce"]), int(challenge["difficulty"])
        expires, sig = int(challenge["expires"]), str(challenge["sig"])
        c_bind = str(challenge["bind"])
    except (KeyError, TypeError, ValueError):
        return False, "[L2] malformed challenge"
    if not (isinstance(counter, (int, str)) and str(counter).isdigit() and len(str(counter)) <= 20):
        return False, "[L2] counter must be a decimal number"
    expected = _sign(secret, "v1", nonce, bits, expires, c_bind)
    if not hmac.compare_digest(expected, sig):
        return False, "[L2] challenge signature invalid (was it edited?)"
    if now > expires:
        return False, "[L2] challenge expired"
    if not hmac.compare_digest(c_bind, bind):
        return False, "[L2] challenge was issued to a different client"
    if not 0 < bits <= MAX_BITS:
        return False, "[L2] difficulty out of range"
    if not meets_difficulty(digest(nonce, counter), bits):
        return False, f"[L2] hash does not have {bits} leading zero bits"
    return True, f"[L2] solved at {bits} bits"


if __name__ == "__main__":
    secret, me = os.urandom(32), client_bind("203.0.113.66")
    c = issue(secret, 8, me)
    from .pow_core import solve
    counter, _ = solve(c["nonce"], 8)
    print("Honest solution:   ", verify(secret, c, counter, me))
    print("Forged difficulty: ", verify(secret, {**c, "difficulty": 0}, counter, me))
    print("Other client:      ", verify(secret, c, counter, client_bind("198.51.100.7")))
    print("After expiry:      ", verify(secret, c, counter, me, now=c["expires"] + 1))
