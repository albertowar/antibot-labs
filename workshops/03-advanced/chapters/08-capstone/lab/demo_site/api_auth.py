"""
Capstone — API tokens bound to the TLS fingerprint (W3 Ch2, W2 Ch5)

W2 Ch6 bound the *login* to a session. The API has the same soft spot one
layer up: a stolen or replayed bearer token is as good as a password. A mobile
app or a partner script that harvests one token can then scrape the API from
anywhere.

The fix reuses the JA4 fingerprint the edge already computes (W2 Ch5): the
token carries a claim equal to a hash of the client's JA4, and every API call
re-checks it. A token minted by a real Chrome and replayed by a Python client
with a different TLS stack no longer matches. This is a *consistency* control,
exactly like JA4 itself: it will not tell two Chrome builds apart, and it does
nothing against a stealth browser that owns the TLS stack it presents. What it
stops is the cheap case — a token lifted out of one client and replayed by
another with a different handshake.

Tokens are short JWTs signed with the lab secret (PyJWT). In production prefer
asymmetric keys so an API node can verify without holding the signing key.
"""

import hashlib
import time

import jwt

ALG = "HS256"
TTL_S = 3600


def ja4_claim(ja4):
    """A short, non-reversible tag for a JA4 string (empty when the edge saw none)."""
    return hashlib.sha256((ja4 or "none").encode()).hexdigest()[:16]


def issue(user_id, ja4, secret, ttl_s=TTL_S):
    now = int(time.time())
    payload = {"sub": str(user_id), "fp": ja4_claim(ja4), "iat": now, "exp": now + ttl_s}
    return jwt.encode(payload, secret, algorithm=ALG)


def verify(token, ja4, secret):
    """Return (ok, claims|reason). ok is False for a missing, bad, expired or
    fingerprint-mismatched token."""
    if not token:
        return False, "no API token"
    token = token[7:] if token.lower().startswith("bearer ") else token
    try:
        claims = jwt.decode(token, secret, algorithms=[ALG])
    except jwt.ExpiredSignatureError:
        return False, "API token expired"
    except jwt.InvalidTokenError:
        return False, "API token invalid signature"
    if claims.get("fp") != ja4_claim(ja4):
        return False, "API token fingerprint mismatch (replayed from another TLS stack)"
    return True, claims


if __name__ == '__main__':
    s = "lab-secret"
    good = issue(42, "t13d1516h2_8daaf6152771_b186095e22b6", s)
    ok, claims = verify(good, "t13d1516h2_8daaf6152771_b186095e22b6", s)
    assert ok and claims["sub"] == "42", (ok, claims)
    ok, why = verify(good, "t13d1516h2_DIFFERENT_b186095e22b6", s)
    assert not ok and "mismatch" in why, (ok, why)
    ok, why = verify("", "x", s); assert not ok, why
    ok, why = verify("garbage.token.here", "x", s); assert not ok, why
    print("api_auth self-test OK:", why)
