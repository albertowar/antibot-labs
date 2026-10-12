"""
W1 Ch8 — Challenge: proof of work on checkout (W1 Ch6).

From Round 4, every checkout must carry a solved proof of work. The
difficulty depends on the request's band (policy.POW_BITS): a clean shopper
pays ~1k hashes (nothing), a "challenge" request ~131k (~1.6 s in a browser).

    challenge = base64url(payload) "." HMAC-SHA256(secret, payload)
    payload   = {"sid": session id, "asn": network, "bits": difficulty,
                 "exp": expiry, "n": random nonce}
    solution  = a counter such that SHA-256(challenge ":" counter) starts
                with `bits` zero bits

The HMAC covers EVERY field, so a client can't lower `bits`, stretch `exp`,
or move the challenge to another session. (The companion repo's old version
signed only the nonce, so clients could set difficulty 1.) The nonce is
burned in Redis on first use (SET NX), so a solution works once.

Binding to the session's network (asn) means a challenge solved on one IP
can't be spent from a proxy on another network. That is what stops wave 3's
browser-to-worker handoff.

What it does NOT do: tell humans from bots. A bot that solves it pays the
same price a human does, and native code pays less than a phone's browser
(W1 Ch6). PoW makes each attempt cost CPU; the session cap makes each
hoodie cost an attempt. Price, not identity.
False positives: no JavaScript means no solution. The no-JS shopper is the
one user this layer always fails; production stores offer a fallback (an
accessible CAPTCHA, W1 Ch5, or a queue) for exactly that case.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

import policy

SECRET = os.environ.get("POW_SECRET", secrets.token_hex(32)).encode()


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue(session, network, bits):
    payload = json.dumps({"sid": session.sid, "asn": str(network.get("asn")), "bits": bits,
                          "exp": int(time.time()) + policy.POW_TTL, "n": secrets.token_hex(8)},
                         separators=(",", ":")).encode()
    mac = hmac.new(SECRET, payload, hashlib.sha256).digest()
    return f"{_b64(payload)}.{_b64(mac)}"


def leading_zero_bits(digest):
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


def solve(challenge, bits):
    """Reference solver (what the page's JavaScript does, in Python)."""
    counter = 0
    prefix = f"{challenge}:".encode()
    while leading_zero_bits(hashlib.sha256(prefix + str(counter).encode()).digest()) < bits:
        counter += 1
    return counter


def verify(redis, challenge, counter, session, network, required_bits):
    """Return (ok, reason)."""
    try:
        payload_b64, mac_b64 = challenge.split(".")
        payload = _unb64(payload_b64)
        if not hmac.compare_digest(_unb64(mac_b64), hmac.new(SECRET, payload, hashlib.sha256).digest()):
            return False, "bad signature"
        data = json.loads(payload)
        counter = int(counter)
    except (ValueError, TypeError):
        return False, "malformed challenge or solution"
    if data["exp"] < time.time():
        return False, "expired"
    if data["sid"] != session.sid:
        return False, "issued to another session"
    if data["asn"] != str(network.get("asn")):
        return False, f"issued on AS{data['asn']}, solved from AS{network.get('asn')}"
    if data["bits"] < required_bits:
        return False, f"difficulty {data['bits']} < required {required_bits}"
    digest = hashlib.sha256(f"{challenge}:{counter}".encode()).digest()
    if leading_zero_bits(digest) < data["bits"]:
        return False, "wrong solution"
    if not redis.set(f"pow:used:{data['n']}", 1, nx=True, ex=policy.POW_TTL):
        return False, "already used"
    return True, "ok"


if __name__ == '__main__':
    import sys
    bits = int(sys.argv[1]) if len(sys.argv) > 1 else 17
    started = time.perf_counter()
    counter = solve("demo-challenge", bits)
    took = time.perf_counter() - started
    print(f"{bits} bits: counter={counter} in {took:.2f}s "
          f"({counter / max(took, 1e-9):,.0f} hashes/s in Python; expected work 2^{bits} = {2 ** bits:,})")
