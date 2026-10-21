"""
Chapter 4 — Challenge tokens and the clearance's bindings (Section 4.3, Round 2)

Two different things, with two different jobs:

  challenge token  "I, the server, asked THIS session to solve THIS nonce
                    with THIS variant before THIS time."  Lives ~60 s, used once.
  clearance        "This session solved a challenge at level L; let it in
                    until it expires."  Lives minutes, used many times (Round 5
                    caps it). The store keeps it server-side, in the session
                    (demo_site/gate.py grant_clearance), and js_gate.py checks the
                    User-Agent it was granted to.

The token is `base64url(json) . base64url(HMAC-SHA256)`. The HMAC means the client
can carry state without being able to edit it. It does NOT hide the content:
anyone can base64-decode the payload. Never put the expected answer (or the
variant's chain) in a token. The old companion-repo lab leaked its seed through
a Flask session cookie exactly this way.

Single use comes from Redis, not from the token: issuing a challenge stores
nonce -> session id with a TTL, and POST /api/challenge/verify GETDELs it. A
signed token alone can be replayed as often as you like until it expires.

Trade-offs:
  - Binding to the session id stops "solve once, share the clearance with
    1,000 workers that each have their own cookie jar". It does not stop an
    attacker who copies the session cookie too (Round 4 does exactly that).
  - Binding to a hash of the User-Agent is cheap and catches lazy handoffs
    (browser solves, `requests` with its default UA scrapes). Real users never
    change UA mid-session... except across a browser auto-update, so keep
    clearance lifetimes shorter than an update cycle.
  - IP binding is the classic next step. It hurts mobile users (IP changes
    between cell towers), CGNAT and dual-stack v4/v6 clients. On localhost
    it's meaningless, so the lab leaves it out. In production, bind to a
    coarse prefix (/24, /48) at most, and only for short-lived clearances.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

CHALLENGE_TTL_S = 60


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(payload, key):
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    mac = _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())
    return f"{body}.{mac}"


def unsign(token, key):
    """Return the payload if the MAC is valid and the token has not expired, else None."""
    try:
        body, mac = token.split(".")
        expected = _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(mac, expected):
            return None
        payload = json.loads(_unb64(body))
    except (ValueError, AttributeError):
        return None
    if payload.get("exp", 0) < time.time():
        return None
    return payload


def ua_hash(user_agent):
    return hashlib.sha256((user_agent or "").encode()).hexdigest()[:16]


def issue_challenge(redis, key, sid, variant_id, level):
    """Create a nonce, remember it for single use, and return (nonce, token)."""
    nonce = secrets.token_hex(8)
    now = time.time()
    redis.set(f"lab:jsc:nonce:{nonce}", sid, ex=CHALLENGE_TTL_S)
    token = sign({"n": nonce, "sid": sid, "v": variant_id, "lvl": level,
                  "iat": now, "exp": now + CHALLENGE_TTL_S}, key)
    return nonce, token


def redeem_challenge(redis, key, token, sid, level):
    """
    Check a challenge token and burn its nonce. Returns (payload, reason):
    payload is None if anything is wrong, and reason says what.
    """
    payload = unsign(token, key)
    if payload is None:
        return None, "bad or expired challenge token"
    if payload["sid"] != sid:
        return None, "challenge was issued to a different session"
    if payload["lvl"] != level:
        return None, "challenge was issued at a different level"
    # TODO (Round 2, optional): swap getdel() for get() and re-run
    # `python attacks/round2_python_port.py --replay`. What changes?
    owner = redis.getdel(f"lab:jsc:nonce:{payload['n']}")
    if owner is None:
        return None, "nonce already used or expired"
    if owner != sid:
        return None, "nonce belongs to a different session"
    return payload, None


if __name__ == "__main__":
    key = b"demo-key"
    token = sign({"n": "abc", "exp": time.time() + 60}, key)
    print("Token:", token)
    print("Anyone can read the payload:", _unb64(token.split(".")[0]).decode())
    tampered = sign({"n": "abc", "exp": time.time() + 3600}, b"wrong-key")
    print("Tampered token accepted?", unsign(tampered, key) is not None)
