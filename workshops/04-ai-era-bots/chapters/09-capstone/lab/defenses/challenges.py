"""
W4 Ch9 Capstone — challenge primitives (GIVEN)

Three kinds of challenge the store can serve, and the one property the
governance scoreboard cares about: whether a person who cannot see the screen
can pass it.

    pow            hash puzzle (W1 Ch6). Software solves it; nobody looks at it.
                   Non-visual by construction. Costs the client CPU, not sight.
    captcha_image  "select the tiles" (W1 Ch5). Here only a label and an answer
                   the lab oracle hands to sighted simulated humans. A
                   screen-reader user cannot pass it; the scoreboard counts
                   that as a block, because it is one (W4 Ch8).
    confirm_code   a one-time code emailed to the account holder (W4 Ch4's
                   step-up). Non-visual, and the only kind a *person* must
                   answer: an unattended farm fails it, a shopper's agent hands
                   it back to the shopper.

issue()/verify() keep the token state in Redis; solve_pow() is the client-side
helper the simulators and attack scripts use.
"""

import hashlib
import json
import secrets

NON_VISUAL = {"pow": True, "confirm_code": True, "captcha_image": False}
POW_BITS = 16
TTL = 600
_WORDS = ["lantern", "trowel", "heron", "kettle", "compass", "anorak", "mallet", "osprey"]


def issue(store, kind, sid, pow_bits=POW_BITS):
    """Create a challenge of `kind` for session `sid`. Returns what the client sees."""
    token = secrets.token_hex(8)
    rec = {"kind": kind, "sid": sid}
    if kind == "pow":
        rec["nonce"] = secrets.token_hex(8)
        rec["bits"] = pow_bits
        shown = {"kind": kind, "token": token, "nonce": rec["nonce"], "bits": pow_bits,
                 "instructions": f"find s such that sha256(nonce + s) has {pow_bits} leading zero bits"}
    elif kind == "captcha_image":
        rec["answer"] = _WORDS[int(token[:2], 16) % len(_WORDS)]
        shown = {"kind": kind, "token": token,
                 "instructions": "select every tile showing the named object (image challenge; no audio alternative)"}
    else:
        raise ValueError(f"issue() does not handle {kind!r}; confirm_code is issued by the checkout step-up")
    shown["non_visual"] = NON_VISUAL[kind]
    store.set(f"chal:{token}", json.dumps(rec), ex=TTL)
    return shown


def answer_for(store, token):
    """Lab oracle: the captcha answer, for the sighted-human simulator only."""
    raw = store.get(f"chal:{token}")
    return json.loads(raw).get("answer") if raw else None


def verify(store, token, payload):
    """Check a submitted answer. Returns (ok, kind, why)."""
    raw = store.get(f"chal:{token}") if token else None
    if not raw:
        return False, None, "unknown or expired challenge token"
    rec = json.loads(raw)
    if rec["kind"] == "pow":
        solution = str(payload.get("solution", ""))
        ok = _pow_ok(rec["nonce"], solution, rec["bits"])
        why = "proof of work accepted" if ok else "proof of work does not meet the target"
    else:
        ok = str(payload.get("answer", "")).strip().lower() == rec["answer"]
        why = "image challenge solved" if ok else "wrong tiles"
    if ok:
        store.delete(f"chal:{token}")
    return ok, rec["kind"], why


def _pow_ok(nonce, solution, bits):
    digest = hashlib.sha256((nonce + solution).encode()).digest()
    value = int.from_bytes(digest[:8], "big")
    return value >> (64 - bits) == 0


def solve_pow(nonce, bits):
    """Client side: brute force. ~2**bits hashes; 16 bits is ~65k, tens of ms."""
    i = 0
    while True:
        s = str(i)
        if _pow_ok(nonce, s, bits):
            return s
        i += 1


if __name__ == '__main__':
    import fakeredis
    import time
    r = fakeredis.FakeStrictRedis(decode_responses=True)
    c = issue(r, "pow", "sid1")
    t0 = time.perf_counter()
    s = solve_pow(c["nonce"], c["bits"])
    print(f"solved {c['bits']}-bit PoW in {(time.perf_counter() - t0) * 1000:.0f} ms:", verify(r, c["token"], {"solution": s}))
    c = issue(r, "captcha_image", "sid1")
    print(verify(r, c["token"], {"answer": answer_for(r, c["token"])}))
