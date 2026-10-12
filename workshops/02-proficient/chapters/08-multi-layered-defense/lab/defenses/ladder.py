"""
Chapter 8: The response ladder's rungs

    pow       hashcash proof-of-work, as in W1 Ch7. Real users' browsers
              solve it in well under a second. A bot pays the same CPU, which
              is nothing for one login and real money for millions.
    step_up   a one-time code emailed to the account (W2 Ch6). Real users pay
              a minute and a context switch. A credential stuffer does not
              own the victims' mailboxes, so it cannot pass. The response
              is the same whether or not the account exists, so the step-up
              itself does not confirm valid usernames.
    block     from Round 3 on, a block is *deceptive*: it looks exactly like
              a wrong password (Section 8.3).

Every rung stores a pending entry for the session, so the request is scored
once. Solving the challenge resumes the original decision; it does not
re-roll the dice.
"""

import hashlib
import json
import secrets

POW_BITS = 15        # ~33k SHA-256 attempts on average
CHALLENGE_TTL = 300  # seconds


def leading_zero_bits(digest):
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


def issue(counters, sid, action, username, cred):
    """Park the login and return what the client must do next."""
    pending = {"action": action, "username": username, "cred": cred}
    if action == "pow":
        pending["prefix"] = secrets.token_hex(8)
    else:
        pending["code"] = f"{secrets.randbelow(10**6):06d}"
        if cred != "unknown_user":
            # The user's inbox (tools/population.py reads it as the real user)
            counters.put(pending["code"], "mailbox", username, ttl=CHALLENGE_TTL)
    counters.put(json.dumps(pending), "pending", sid, ttl=CHALLENGE_TTL)
    if action == "pow":
        return {"action": "challenge", "pow": {"prefix": pending["prefix"], "bits": POW_BITS}}
    return {"action": "verify", "message": "If this account exists, we emailed it a sign-in code."}


def resolve(counters, sid, pow_nonce=None, code=None):
    """Check a challenge answer. Returns the parked entry, or None if it fails."""
    raw = counters.fetch("pending", sid)
    if raw is None:
        return None
    pending = json.loads(raw)
    if pending["action"] == "pow" and pow_nonce is not None:
        digest = hashlib.sha256(f"{pending['prefix']}:{pow_nonce}".encode()).digest()
        ok = leading_zero_bits(digest) >= POW_BITS
    elif pending["action"] == "step_up" and code is not None:
        ok = secrets.compare_digest(code, pending["code"])
    else:
        ok = False
    if ok:
        counters.drop("pending", sid)  # single use
        return pending
    return None
