"""
token_binding (Round 4): the login must carry a token that proves the page's JavaScript ran IN THIS
SESSION. Enabled at DEFENSE_LEVEL >= 5.

The login API is the soft spot of every earlier round: it accepts a bare POST, so a credential stuffer
needs no browser at all. From level 5 a login must carry a token (header `X-Login-Token`, or a
`login_token` form or JSON field), minted like this:

    1. the page's sensor posts its report; the server derives a fingerprint hash from it
    2. GET  /api/login/challenge   -> {nonce, bits, fp_hash}      (demo_site/ext/login9.py)
    3. the page finds a counter with sha256(nonce:fp_hash:counter) starting with `bits` zero bits
       (~16k hashes, a fraction of a second in a browser)
    4. POST /api/login/token {nonce, counter} -> a token: Chapter 4's signed, expiring payload
       {sid, fp, exp} (defenses/tokens.py, copied from W2 Ch4)
    5. the login carries it; this check verifies the signature, the expiry, the session and the
       fingerprint hash

    No valid token  NO_TOKEN_POINTS

Trade-off, and the lesson of W2 Ch4: the token is not a secret and not a CAPTCHA. Anyone who reads the
page's JavaScript can reproduce it in Python (attacks/round4_stuffing.py --with-token does exactly
that), and the proof of work costs a farm almost nothing. What it buys is BINDING: every login attempt
is now tied to one session and one fingerprint hash, so login_risk.py can count failures per
fingerprint instead of per IP. Residential proxies make per-IP counts useless.
"""

import hashlib
import json
import secrets
import time

from . import policy, tokens
from .pipeline import Check, Signal

KEY = b"w2-ch9-lab-token-key"          # lab only: a real key is a secret, rotated, kept out of the repo
CHALLENGE_TTL_S = 120
HEADER = "X-Login-Token"
# What a browser reports about itself that does not change between page loads. A different value
# here is, by definition, a different "device" to login_risk.
STABLE = ("ua", "platform", "languages", "hardware_concurrency", "max_touch_points")


def fingerprint_hash(signals):
    """A stable id for 'this browser on this machine', from the sensor report (W2 Ch1)."""
    if not signals:
        return ""
    stable = {k: signals.get(k) for k in STABLE}
    stable["gpu"] = (signals.get("webgl") or {}).get("renderer")
    geometry = signals.get("geometry") or {}
    stable["screen"] = [geometry.get("screen_w"), geometry.get("screen_h")]
    stable["brands"] = (signals.get("uad") or {}).get("brands")
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()[:16]


def zero_bits(digest):
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


def issue(redis, sid, fp_hash):
    nonce = secrets.token_hex(8)
    redis.set(f"lab:logintok:{nonce}", sid, ex=CHALLENGE_TTL_S)
    return {"nonce": nonce, "bits": policy.TOKEN_BITS, "fp_hash": fp_hash}


def redeem(redis, sid, fp_hash, nonce, counter):
    """Check a solution and return a token, or None."""
    if not fp_hash or not isinstance(counter, int):
        return None
    if redis.getdel(f"lab:logintok:{nonce}") != sid:        # unknown, expired, used, or another session's
        return None
    if zero_bits(hashlib.sha256(f"{nonce}:{fp_hash}:{counter}".encode()).digest()) < policy.TOKEN_BITS:
        return None
    return tokens.sign({"sid": sid, "fp": fp_hash, "exp": time.time() + policy.TOKEN_TTL_S}, KEY)


def token_ok(ctx):
    from . import sensor
    body = ctx.json if isinstance(ctx.json, dict) else {}
    token = ctx.header(HEADER) or ctx.form.get("login_token") or body.get("login_token") or ""
    payload = tokens.unsign(token, KEY)
    return bool(payload and payload.get("sid") == ctx.session.sid
                and payload.get("fp") == fingerprint_hash(sensor.report(ctx)))


def _check(ctx):
    if token_ok(ctx):
        return None
    return [Signal("token_binding", "no_valid_token", policy.NO_TOKEN_POINTS,
                   "no valid login token: this session's page JavaScript never solved the challenge")]


CHECK = Check("token_binding", _check, phases=("action:login",))


if __name__ == "__main__":
    print(zero_bits(bytes([0, 0, 0x0F, 0xFF])))     # 20
