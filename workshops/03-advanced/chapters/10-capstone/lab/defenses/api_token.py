"""
Level 5: API tokens bound to the TLS fingerprint (W3 Ch2, W2 Ch3).

W2 Ch6 bound the *login* to a session. The API has the same soft spot one layer up: a stolen or replayed bearer
token is as good as a password. A mobile app or a partner script that harvests one token can scrape the API from
anywhere.

The fix reuses the JA4 fingerprint the edge already hands the store: the token carries a claim equal to a hash of
the client's JA4 a+b (the TLS family and cipher set; part c is not used, defenses/ja4.py explains why), and
every API call re-checks it. A token minted by a real Safari and replayed by a Python client with a different TLS
stack no longer matches. This is a *consistency* control, exactly like JA4 itself: it will not tell two Chrome
builds apart, and it does nothing against a stealth browser that owns the TLS stack it presents. What it stops is
the cheap case, a token lifted out of one client and replayed by another with a different handshake.

In this lab the JA4 is CLAIMED (`X-Lab-JA4`), not measured: there is no TLS edge in front of the store (W2 Ch3
teaches the measured version). The binding logic is the same.

Tokens are short JWTs signed with the store's secret (PyJWT, HS256). In production prefer asymmetric keys, so an
API node can verify without holding the signing key.
"""

import hashlib
import time

import jwt

ALG = "HS256"


def ja4_claim(ja4_ab):
    """A short, non-reversible tag for a JA4 a+b string (empty when the store saw none)."""
    return hashlib.sha256((ja4_ab or "none").encode()).hexdigest()[:16]


def issue(user_id, ja4_ab, secret, ttl_s=3600):
    now = int(time.time())
    return jwt.encode({"sub": str(user_id), "fp": ja4_claim(ja4_ab), "iat": now, "exp": now + ttl_s}, secret, algorithm=ALG)


def verify(token, ja4_ab, secret):
    """Return (ok, claims | reason). ok is False for a missing, bad, expired or fingerprint-mismatched token."""
    if not token:
        return False, "no API token"
    token = token[7:] if token.lower().startswith("bearer ") else token
    try:
        claims = jwt.decode(token, secret, algorithms=[ALG])
    except jwt.ExpiredSignatureError:
        return False, "API token expired"
    except jwt.InvalidTokenError:
        return False, "API token invalid signature"
    if claims.get("fp") != ja4_claim(ja4_ab):
        return False, "API token fingerprint mismatch (replayed from another TLS stack)"
    return True, claims


if __name__ == "__main__":
    s = "lab-secret-0123456789-0123456789-0123"
    ab = "t13d2013h2_a09f3c656075"
    good = issue(42, ab, s)
    ok, claims = verify(good, ab, s)
    assert ok and claims["sub"] == "42", (ok, claims)
    ok, why = verify(good, "t13d1516h2_8daaf6152771", s)
    assert not ok and "mismatch" in why, (ok, why)
    ok, why = verify("", ab, s)
    assert not ok, why
    ok, why = verify("garbage.token.here", ab, s)
    assert not ok, why
    print("api_token self-test OK:", why)
