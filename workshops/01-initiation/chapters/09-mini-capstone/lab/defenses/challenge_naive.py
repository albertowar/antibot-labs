"""
Chapter 7 — Round 1 Defense (L1): a PoW gate with a naive verifier

This is the design most first implementations end up with, and it is
close to the code in many tutorials:

  GET  /api/challenge?type=pow  (or the gate's 403 payload) -> {"nonce": ..., "difficulty": 16, "issued_at": ...}
  POST /api/challenge/verify  <- {"type": "pow", "answer": {"challenge": <the same JSON>, "counter": ...}}

It looks reasonable, but it is broken. The server keeps no state, so it
trusts the challenge the *client* sends back, including `difficulty`.
Send difficulty 0 and every counter is a valid solution.

This is not hypothetical: Anubis, the PoW proxy used by GNOME, kernel.org
and FFmpeg, shipped this bug (CVE-2025-24369, fixed in January 2025).

What else is wrong here (you fix these in Round 2):
  - no signature: nonce and difficulty can be invented by the client
  - no expiry: a solution found now is still valid next year
  - no binding: a solution found on one machine works on any other
  - no spend tracking: one solution can be redeemed again and again
"""

from __future__ import annotations

import os
import time

from .pow_core import digest, meets_difficulty


def issue(difficulty: int) -> dict:
    return {"nonce": os.urandom(16).hex(), "difficulty": difficulty,
            "issued_at": int(time.time())}


def verify(challenge: dict, counter) -> tuple[bool, str]:
    """Check the client's solution against the client's challenge. (The bug.)"""
    try:
        nonce, bits = str(challenge["nonce"]), int(challenge["difficulty"])
    except (KeyError, TypeError, ValueError):
        return False, "[L1] malformed challenge"
    if not meets_difficulty(digest(nonce, counter), bits):
        return False, f"[L1] hash does not have {bits} leading zero bits"
    return True, f"[L1] solved at {bits} bits"


if __name__ == "__main__":
    c = issue(16)
    print("Issued:", c)
    print("Honest junk answer:", verify(c, "0"))
    print("Forged difficulty: ", verify({**c, "difficulty": 0}, "0"))
