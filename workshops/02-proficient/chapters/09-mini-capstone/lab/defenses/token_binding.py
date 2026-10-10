"""
Chapter 9 — L4 login token binding (W2 Ch2), enabled at DEFENSE_LEVEL >= 4

The login API is the soft spot: until Round 4 it accepts a bare POST, so a
credential stuffer doesn't need a browser at all. From Level 4, a login must
carry a token that proves the page's JavaScript ran *in this session*:

    1. the page sends telemetry; the server stores its fingerprint hash
    2. GET /api/challenge  -> nonce (single use, 120 s)
    3. the page finds a counter with sha256(nonce:fp_hash:counter) starting
       with DIFFICULTY zero bits (~16k hashes, ~0.2 s in a browser)
    4. POST /api/challenge/verify -> token = sid.fp_hash.expiry.HMAC
    5. POST /api/login with X-Lab-Token; verify() checks HMAC, expiry, sid
       and fingerprint hash

    No valid token  +60

Trade-off: the token is not a secret and not a CAPTCHA. Anyone who reads
challenge.js can re-implement it (W2 Ch2), and the PoW costs a bot farm
almost nothing. What it buys is *binding*: every attempt is now tied to one
session and one fingerprint hash, so login_risk.py can count failures per
fingerprint instead of per IP. Residential proxies make per-IP counts useless.
"""

import hashlib
import hmac
import secrets
import time

DIFFICULTY = 14
CHALLENGE_TTL_S = 120
TOKEN_TTL_S = 120


def leading_zero_bits(digest):
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


def issue_challenge(store, sid):
    nonce = secrets.token_hex(16)
    store.set(f"chal:{sid}:{nonce}", "1", ex=CHALLENGE_TTL_S)
    return {"nonce": nonce, "difficulty": DIFFICULTY}


def _sign(secret, payload):
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]


def redeem(store, sid, fp_hash, nonce, counter, secret):
    """Check a challenge solution; return a login token or None."""
    if not fp_hash or not nonce or not isinstance(counter, int):
        return None
    if not store.delete(f"chal:{sid}:{nonce}"):  # unknown, expired or already used
        return None
    digest = hashlib.sha256(f"{nonce}:{fp_hash}:{counter}".encode()).digest()
    if leading_zero_bits(digest) < DIFFICULTY:
        return None
    payload = f"{sid}.{fp_hash}.{int(time.time()) + TOKEN_TTL_S}"
    return f"{payload}.{_sign(secret, payload)}"


def verify(token, sid, fp_hash, secret):
    try:
        tok_sid, tok_fp, expiry, sig = token.split(".")
    except ValueError:
        return False
    payload = f"{tok_sid}.{tok_fp}.{expiry}"
    return (hmac.compare_digest(sig, _sign(secret, payload))
            and tok_sid == sid and tok_fp == fp_hash and int(expiry) >= time.time())


def score_token(token_ok):
    if token_ok:
        return 0, []
    return 60, ["No valid login token: this session's page JavaScript never solved the challenge"]


if __name__ == '__main__':
    print(leading_zero_bits(bytes([0, 0, 0x0F, 0xFF])))  # 20
